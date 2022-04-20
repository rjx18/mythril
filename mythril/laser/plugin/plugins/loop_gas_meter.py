from mythril.laser.ethereum.svm import LaserEVM
from mythril.laser.plugin.interface import LaserPlugin
from mythril.laser.plugin.builder import PluginBuilder
from mythril.laser.plugin.signals import PluginSkipState
from mythril.laser.plugin.plugins.plugin_annotations import (
    LoopGasMeterAnnotation,
    LoopGasMeterItem,
    TraceItem
)
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.transaction.transaction_models import (
    ContractCreationTransaction,
)
from mythril.exceptions import UnsatError
from mythril.analysis import solver
from typing import cast, List, Dict, Set
import logging

from mythril.laser.ethereum.instruction_data import get_opcode_gas, calculate_sha3_gas

from mythril.support.signatures import SignatureDB

log = logging.getLogger(__name__)

def get_loop_gas_meter_annotation(state: GlobalState) -> LoopGasMeterAnnotation:
    """Returns a loop gas meter annotation

    :param state: A global state object
    """

    annotations = cast(
        List[LoopGasMeterAnnotation], list(state.get_annotations(LoopGasMeterAnnotation))
    )
    
    if len(annotations) == 0:
        print("Annotation not found")
        annotation = LoopGasMeterAnnotation()
        state.annotate(annotation)
    else:
        annotation = annotations[0]

    return annotation

class LoopGasMeterBuilder(PluginBuilder):
    name = "loop-gas-meter"

    def __call__(self, *args, **kwargs):
        return LoopGasMeter(kwargs["contract"])

class LoopGasMeter(LaserPlugin):
    """Dependency Pruner Plugin

    For every insturction, this plugin keeps a list of storage locations that
    are accessed (read) in the execution path containing that block. This map
    is built up over the whole symbolic execution run.

    After the initial build up of the map in the first transaction, blocks are
    executed only if any of the storage locations written to in the previous
    transaction can have an effect on that block or any of its successors.
    """

    def __init__(self, contract):
        """Creates LoopGasMeter"""
        self._reset()
        self.contract = contract

    def _reset(self):
        self.global_loop_gas_meter = {}
        self.is_creation = True

    def initialize(self, symbolic_vm: LaserEVM) -> None:
        """Initializes the LoopGasMeter

        :param symbolic_vm
        """
        self._reset()
        
        @symbolic_vm.laser_hook("start_sym_trans")
        def start_sym_trans_hook():
          self.is_creation = False
          
        @symbolic_vm.instr_hook("pre", None)
        def add_pre_hook(op_code: str):
            def add_opcode_pre_hook(state: GlobalState):
                annotation = get_loop_gas_meter_annotation(state)
                
                pc = state.instruction["address"]
                
                source_info = self.contract.get_source_mapping(pc, constructor=self.is_creation)
                if (self.contract.has_source(source_info.solidity_file_idx)):
                    annotation.curr_key = f'{source_info.offset}:{source_info.offset + source_info.length}:{source_info.solidity_file_idx}'
            return add_opcode_pre_hook

# Need 2 matches to prevent too many false positives?

# ci: A        ci: A       ci: A       ci: A
# lj: None     lj: A       lj: C       lj: B
# A         -> B        -> C        -> A ->                                 B                                     -> C === 
# A            A, B        A, B, C     A, B, C, A  --> FOUND! Remove        A, B          A, B, C
# Keep gas count at each trace location

# ci: A        ci: A       ci: A       ci: A
# lj: None     lj: A       lj: B       lj: C
# A             -> B        -> C            -> B          ->      C ->                      A                         B             C                              === 
# |A            |A, |B        |A, |B, |C     |A, |B, |C, |B       |A, |B, |C, |B, |C        A, B, C, A ===> Found!    A, B,         A, B, C
#                                                                      i  i+1 len-2 len-1 
        @symbolic_vm.pre_hook("JUMPDEST")
        def check_jumpdest_arg(state: GlobalState):
            annotation = get_loop_gas_meter_annotation(state)
            
            pc = state.instruction["address"]
            
            current_trace_item = TraceItem(pc, state.mstate.max_gas_used)
            annotation.trace.append(current_trace_item)
            
            (loop_head, loop_gas) = find_loop(annotation.trace)
            
            if loop_head is not None:
                source_info = self.contract.get_source_mapping(loop_head, constructor=self.is_creation)
            
                if (self.contract.has_source(source_info.solidity_file_idx)):
                    annotation.curr_key = f'{source_info.offset}:{source_info.offset + source_info.length}:{source_info.solidity_file_idx}'
                    is_hidden_jumpdest = False
                else:
                    is_hidden_jumpdest = True
                    
                if (annotation.curr_key not in annotation.loop_gas_meter):
                    annotation.loop_gas_meter[annotation.curr_key] = dict()
                
                key_gas_items = annotation.loop_gas_meter[annotation.curr_key]
                
                if (loop_head not in key_gas_items):
                    key_gas_items[loop_head] = LoopGasMeterItem(is_hidden=is_hidden_jumpdest)
                    
                loop_gas_item = key_gas_items[loop_head]
                loop_gas_item.iteration_gas_cost.append(loop_gas)
            
        @symbolic_vm.pre_hook("STOP")
        def stop_hook(state: GlobalState):
            _transaction_end(state)

        @symbolic_vm.pre_hook("RETURN")
        def return_hook(state: GlobalState):
            _transaction_end(state)
            
        @symbolic_vm.pre_hook("REVERT")
        def revert_hook(state: GlobalState):
            _transaction_end(state)

        def find_loop(trace):
            found_loop_head = None
            
            loop_head_index = 0
            
            for loop_head_index in range(len(trace) - 3, -1, -1):
                if trace[loop_head_index].pc == trace[-2].pc and trace[loop_head_index + 1].pc == trace[-1].pc:
                    found_loop_head = trace[loop_head_index]
                    break
            
            if found_loop_head:
                found_pc = found_loop_head.pc
                found_gas = found_loop_head.gas
                
                loop_iteration_gas = trace[-2].gas - found_gas
                
                # remove loop from trace to prevent finding it again next time
                for i in range(len(trace) - 3, loop_head_index - 1, -1):
                    del trace[i]
                
                return (found_pc, loop_iteration_gas)
            else:
                return (None, 0)
            

        def _transaction_end(state: GlobalState) -> None:
            """When a stop or return is reached, the storage locations read along the path are entered into
            the dependency map for all nodes encountered in this path.

            :param state:
            """

            annotation = get_loop_gas_meter_annotation(state)
            
            for key in annotation.loop_gas_meter.keys():
                if key not in self.global_loop_gas_meter:
                    self.global_loop_gas_meter[key] = dict()
                    
                key_gas_items = self.global_loop_gas_meter[key]
                
                annotation_key_gas_items = annotation.loop_gas_meter[key]
                    
                for pc in annotation_key_gas_items:
                    annotation_pc_gas_item = annotation_key_gas_items[pc]
                    
                    if pc not in key_gas_items:
                        key_gas_items[pc] = LoopGasMeterItem(is_hidden=annotation_pc_gas_item.is_hidden)
                        
                    current_global_gas_item = key_gas_items[pc]
                    current_global_gas_item.merge(annotation_pc_gas_item)
            
        # @symbolic_vm.laser_hook("add_world_state")
        # def world_state_filter_hook(state: GlobalState):
        #     _transaction_end(state)
            
