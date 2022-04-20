from mythril.laser.ethereum.svm import LaserEVM
from mythril.laser.plugin.interface import LaserPlugin
from mythril.laser.plugin.builder import PluginBuilder
from mythril.laser.plugin.signals import PluginSkipState
from mythril.laser.plugin.plugins.plugin_annotations import (
    FunctionTrackerAnnotation,
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

def get_function_tracker_annotation(state: GlobalState) -> FunctionTrackerAnnotation:
    """Returns a functional gas meter annotation

    :param state: A global state object
    """

    annotations = cast(
        List[FunctionTrackerAnnotation], list(state.get_annotations(FunctionTrackerAnnotation))
    )
    
    if len(annotations) == 0:
        print("Annotation not found")
        annotation = FunctionTrackerAnnotation()
        state.annotate(annotation)
    else:
        annotation = annotations[0]

    return annotation

class FunctionTrackerBuilder(PluginBuilder):
    name = "function-tracker"

    def __call__(self, *args, **kwargs):
        return FunctionTracker()

class FunctionTracker(LaserPlugin):
    """Dependency Pruner Plugin

    For every insturction, this plugin keeps a list of storage locations that
    are accessed (read) in the execution path containing that block. This map
    is built up over the whole symbolic execution run.

    After the initial build up of the map in the first transaction, blocks are
    executed only if any of the storage locations written to in the previous
    transaction can have an effect on that block or any of its successors.
    """

    def __init__(self):
        """Creates FunctionTracker"""
        self._reset()

    def _reset(self):
        self.signatures = SignatureDB()
        self.function_gas_meter = {}

    def initialize(self, symbolic_vm: LaserEVM) -> None:
        """Initializes the FunctionTracker

        :param symbolic_vm
        """
        self._reset()

        @symbolic_vm.pre_hook("PUSH4")
        def check_push_arg(state: GlobalState):
            print("Executing push hook!")
            if not isinstance(state.current_transaction, ContractCreationTransaction):
              annotation = get_function_tracker_annotation(state)
              
              push_value = state.instruction["argument"]
              
              if (annotation.current_function == None):
                if type(push_value) == tuple:
                    parsed_value = "0x"
                    for byte in push_value:
                        parsed_byte = '{:02x}'.format(byte)
                        parsed_value += parsed_byte
                else: 
                    parsed_value = push_value.lower()
            
                print(f'MY_DEBUG FT Found a function being pushed: {parsed_value}')
            
                if (parsed_value in self.signatures.solidity_sigs and state.environment.code.instruction_list[state.mstate.pc + 1]["opcode"] == "EQ"):
                    fn_name = self.signatures.solidity_sigs[parsed_value][0]
                    annotation.last_seen_function = f'{parsed_value}:{fn_name}'
                    print(f'MY_DEBUG FT pushed function: {parsed_value}')
            
            # print("MY_DEBUG current max gas for pc " + str(pc) + " is " + str(state.mstate.pc_gas_meter[pc].max_opcode_gas_used))
            
        @symbolic_vm.post_hook("JUMPI")
        def check_jumpi(state: GlobalState):
            annotation = get_function_tracker_annotation(state)
            current_function = annotation.current_function or "None"
            last_seen_function = annotation.last_seen_function or "None"
            print("Current function: " + current_function)
            print("Last seen function: " + last_seen_function)
            if not isinstance(state.current_transaction, ContractCreationTransaction):
              if annotation.current_function == None and annotation.last_seen_function != None:
                
                prev_pc = state.mstate.prev_pc
                curr_pc = state.mstate.pc
                print("prev_pc" + str(prev_pc))
                print("curr_pc" + str(curr_pc))
                
                is_function_jump = prev_pc + 1 != curr_pc
                
                if (is_function_jump):
                  print("Executing adding current function: " + last_seen_function)
                  annotation.current_function = annotation.last_seen_function
                
                annotation.last_seen_function = None

        @symbolic_vm.pre_hook("STOP")
        def stop_hook(state: GlobalState):
            _transaction_end(state)

        @symbolic_vm.pre_hook("RETURN")
        def return_hook(state: GlobalState):
            _transaction_end(state)
            
        @symbolic_vm.pre_hook("REVERT")
        def revert_hook(state: GlobalState):
            _transaction_end(state)

        def _transaction_end(state: GlobalState) -> None:
            """When a stop or return is reached, the storage locations read along the path are entered into
            the dependency map for all nodes encountered in this path.

            :param state:
            """

            annotation = get_function_tracker_annotation(state)
            
            if (annotation.current_function != None):
              prev_max_gas = self.function_gas_meter.get(annotation.current_function, 0)
              self.function_gas_meter[annotation.current_function] = max(prev_max_gas, state.mstate.max_gas_used)

              print("Current function " + annotation.current_function + " gas meter: " + str(self.function_gas_meter))

        # @symbolic_vm.laser_hook("add_world_state")
        # def world_state_filter_hook(state: GlobalState):
        #     _transaction_end(state)
            
