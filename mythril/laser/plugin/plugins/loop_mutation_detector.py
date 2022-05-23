from mythril.laser.ethereum.svm import LaserEVM
from mythril.laser.plugin.interface import LaserPlugin
from mythril.laser.plugin.builder import PluginBuilder
from mythril.laser.plugin.signals import PluginSkipState
from mythril.laser.plugin.plugins.plugin_annotations import (
    FunctionTrackerAnnotation,
)
from mythril.laser.plugin.plugins.gas_meter import get_gas_meter_annotation
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

from mythril.laser.ethereum.strategy.extensions.bounded_loops import JumpdestCountAnnotation

log = logging.getLogger(__name__)

def get_jumpdest_count_annotation(state: GlobalState) -> FunctionTrackerAnnotation:
    """Returns a functional gas meter annotation

    :param state: A global state object
    """

    annotations = cast(
        List[JumpdestCountAnnotation],
        list(state.get_annotations(JumpdestCountAnnotation)),
    )

    if len(annotations) == 0:
        annotation = JumpdestCountAnnotation()
        state.annotate(annotation)
    else:
        annotation = annotations[0]

    return annotation

class LoopMutationDetectorBuilder(PluginBuilder):
    name = "loop-mutation-detector"

    def __call__(self, *args, **kwargs):
        return LoopMutationDetector(kwargs["contract"])

class LoopMutationDetector(LaserPlugin):
    """Dependency Pruner Plugin

    For every insturction, this plugin keeps a list of storage locations that
    are accessed (read) in the execution path containing that block. This map
    is built up over the whole symbolic execution run.

    After the initial build up of the map in the first transaction, blocks are
    executed only if any of the storage locations written to in the previous
    transaction can have an effect on that block or any of its successors.
    """

    def __init__(self, contract):
        """Creates LoopMutationDetector"""
        self._reset()
        self.contract = contract

    def _reset(self):
        self.detected_keys = set()
        self.is_creation = True
        
    def check_in_explicit_loop(self, trace: List[int]) -> int:
        """
        Checks if the current SSTORE is within an explicit loop
        :param trace: annotation trace
        :return:
        """
        for i in range(len(trace) - 3, -1, -1):
            if trace[i] == trace[-2] and trace[i + 1] == trace[-1]:
              return True

        return False

    def initialize(self, symbolic_vm: LaserEVM) -> None:
        """Initializes the LoopMutationDetector

        :param symbolic_vm
        """
        self._reset()
        
        @symbolic_vm.laser_hook("start_sym_trans")
        def start_sym_trans_hook():
          self.is_creation = False

        @symbolic_vm.instr_hook("gas", "SSTORE")
        def sstore_hook(state: GlobalState):
            # print("Executing push hook!")
            annotation = get_jumpdest_count_annotation(state)
            
            in_loop = self.check_in_explicit_loop(annotation.trace)
            
            if in_loop:
              gas_annotation = get_gas_meter_annotation(state)
              
              if gas_annotation.curr_key is not None:
                self.detected_keys.add(gas_annotation.curr_key)
            
            # print("MY_DEBUG current max gas for pc " + str(pc) + " is " + str(state.mstate.pc_gas_meter[pc].max_opcode_gas_used))
          
        
        @symbolic_vm.instr_hook("gas", "SLOAD")
        def sload_hook(state: GlobalState):
            # print("Executing push hook!")
            annotation = get_jumpdest_count_annotation(state)
            
            in_loop = self.check_in_explicit_loop(annotation.trace)
            
            if in_loop:
              gas_annotation = get_gas_meter_annotation(state)
              
              if gas_annotation.curr_key is not None:
                self.detected_keys.add(gas_annotation.curr_key)
            
            # print("MY_DEBUG current max gas for pc " + str(pc) + " is " + str(state.mstate.pc_gas_meter[pc].max_opcode_gas_used))
          
