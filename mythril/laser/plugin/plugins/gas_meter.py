from mythril.laser.ethereum.svm import LaserEVM
from mythril.laser.plugin.interface import LaserPlugin
from mythril.laser.plugin.builder import PluginBuilder
from mythril.laser.plugin.signals import PluginSkipState
from mythril.laser.plugin.plugins.plugin_annotations import (
    GasMeterTrackerAnnotation,
    GasMeterItem
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

log = logging.getLogger(__name__)

def get_gas_meter_annotation(state: GlobalState) -> GasMeterTrackerAnnotation:
    """Returns a functional gas meter annotation

    :param state: A global state object
    """

    annotations = cast(
        List[GasMeterTrackerAnnotation], list(state.get_annotations(GasMeterTrackerAnnotation))
    )

    if len(annotations) == 0:
        # print("Annotation not found")
        annotation = GasMeterTrackerAnnotation()
        state.annotate(annotation)
    else:
        annotation = annotations[0]

    return annotation

class GasMeterBuilder(PluginBuilder):
    name = "gas-meter"

    def __call__(self, *args, **kwargs):
        return GasMeter(kwargs["contract"])

class GasMeter(LaserPlugin):
    """Dependency Pruner Plugin

    For every insturction, this plugin keeps a list of storage locations that
    are accessed (read) in the execution path containing that block. This map
    is built up over the whole symbolic execution run.

    After the initial build up of the map in the first transaction, blocks are
    executed only if any of the storage locations written to in the previous
    transaction can have an effect on that block or any of its successors.
    """

    def __init__(self, contract):
        """Creates GasMeter"""
        self._reset()
        self.contract = contract

    def _reset(self):
      self.runtime_gas_meter = {}
      self.creation_gas_meter = {}
      self.is_creation = True
      
    def current_gas_meter(self):
        return self.creation_gas_meter if self.is_creation else self.runtime_gas_meter

    def initialize(self, symbolic_vm: LaserEVM) -> None:
        """Initializes the DependencyPruner

        :param symbolic_vm
        """
        self._reset()

        # @symbolic_vm.laser_hook("start_sym_exec")
        # start of sym execution, set to creation first
        
        @symbolic_vm.laser_hook("start_sym_trans")
        def start_sym_trans_hook():
          self.is_creation = False
        # start of sym execution, set to runtime
        

        @symbolic_vm.instr_hook("gas", None)
        def add_gas_hook(op_code: str):
            def add_opcode_gas_hook(state: GlobalState):
                annotation = get_gas_meter_annotation(state)
                
                # opcode = state.instruction["opcode"]
                pc = state.instruction["address"]
                
                # print(f'Calling gas hook for {op_code} at {pc}')
                
                source_info = self.contract.get_source_mapping(pc, constructor=self.is_creation)
                if (self.contract.has_source(source_info.solidity_file_idx)):
                    annotation.curr_key = f'{source_info.offset}:{source_info.offset + source_info.length}:{source_info.solidity_file_idx}'
                
                if annotation.curr_key is not None:
                    min_gas_used = state.mstate.min_gas_used - annotation.last_seen_min_gas
                    max_gas_used = state.mstate.max_gas_used - annotation.last_seen_max_gas
                    mem_gas_used = state.mstate.mem_gas_used - annotation.last_seen_mem_gas
                    min_storage_gas_used = state.mstate.min_storage_gas_used - annotation.last_seen_min_storage_gas
                    max_storage_gas_used = state.mstate.max_storage_gas_used - annotation.last_seen_max_storage_gas
                    
                    gas_meter_item = annotation.gas_meter.get(annotation.curr_key, GasMeterItem())
                    gas_meter_item.mem_gas_used += mem_gas_used
                    gas_meter_item.min_storage_gas_used += min_storage_gas_used
                    gas_meter_item.max_storage_gas_used += max_storage_gas_used
                    gas_meter_item.min_opcode_gas_used += min_gas_used - mem_gas_used - min_storage_gas_used
                    gas_meter_item.max_opcode_gas_used += max_gas_used - mem_gas_used - max_storage_gas_used
                    
                    gas_meter_item.num_invocations += 1
                    
                    annotation.last_seen_min_gas = state.mstate.min_gas_used
                    annotation.last_seen_max_gas = state.mstate.max_gas_used
                    annotation.last_seen_mem_gas = state.mstate.mem_gas_used
                    annotation.last_seen_min_storage_gas = state.mstate.min_storage_gas_used
                    annotation.last_seen_max_storage_gas = state.mstate.max_storage_gas_used
                    
                    # if pc not in self.curr_tx_seen_pc:
                    #   gas_meter_item.num_tx += 1
                    #   self.curr_tx_seen_pc.add(pc)
                    
                    annotation.gas_meter[annotation.curr_key] = gas_meter_item
                
                # print("MY_DEBUG current max gas for pc " + str(pc) + " at " + annotation.curr_key + " is " + str(gas_meter_item.max_opcode_gas_used))
            return add_opcode_gas_hook

        @symbolic_vm.pre_hook("STOP")
        def stop_hook(state: GlobalState):
            _transaction_end(state)

        @symbolic_vm.pre_hook("RETURN")
        def return_hook(state: GlobalState):
            _transaction_end(state)
            
        @symbolic_vm.pre_hook("REVERT")
        def revert_hook(state: GlobalState):
            _transaction_end(state)
            
        @symbolic_vm.laser_hook("skip_state")
        def skip_hook(state: GlobalState):
            _transaction_end(state)

        def _transaction_end(state: GlobalState) -> None:
            """When a stop or return is reached, the storage locations read along the path are entered into
            the dependency map for all nodes encountered in this path.

            :param state:
            """

            annotation = get_gas_meter_annotation(state)
            
            # print("transaction ended!, num keys: " + str(len(annotation.gas_meter.keys())))
            
            for key in annotation.gas_meter.keys():
              if key not in self.current_gas_meter():
                self.current_gas_meter()[key] = GasMeterItem(num_tx=0)
              
              current_global_gas_item = self.current_gas_meter()[key]
              annotation_pc_gas_item = annotation.gas_meter[key]
              
              current_global_gas_item.merge(annotation_pc_gas_item)
              
            #   print("MY_DEBUG transaction ended, current max gas meter for key " + str(key) + " is " + str(current_global_gas_item.max_opcode_gas_used) + " and num_tx is " + str(current_global_gas_item.num_tx))

