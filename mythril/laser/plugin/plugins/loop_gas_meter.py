from mythril.laser.ethereum.svm import LaserEVM
from mythril.laser.plugin.interface import LaserPlugin
from mythril.laser.plugin.builder import PluginBuilder
from mythril.laser.plugin.signals import PluginSkipState
from mythril.laser.plugin.plugins.plugin_annotations import (
    LoopGasMeterAnnotation,
    LoopGasMeterItem,
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
        return LoopGasMeter()

class LoopGasMeter(LaserPlugin):
    """Dependency Pruner Plugin

    For every insturction, this plugin keeps a list of storage locations that
    are accessed (read) in the execution path containing that block. This map
    is built up over the whole symbolic execution run.

    After the initial build up of the map in the first transaction, blocks are
    executed only if any of the storage locations written to in the previous
    transaction can have an effect on that block or any of its successors.
    """

    def __init__(self):
        """Creates LoopGasMeter"""
        self._reset()

    def _reset(self):
        self.global_loop_gas_meter = {}

    def initialize(self, symbolic_vm: LaserEVM) -> None:
        """Initializes the LoopGasMeter

        :param symbolic_vm
        """
        self._reset()

        @symbolic_vm.pre_hook("JUMPDEST")
        def check_jumpdest_arg(state: GlobalState):
            print("Executing jumpdest hook for loop gas meter!")
            annotation = get_loop_gas_meter_annotation(state)
            
            pc = state.instruction["address"]
            
            loop_gas_item = annotation.loop_gas_meter.get(pc, LoopGasMeterItem)
            
            if (loop_gas_item.last_seen_gas_cost != None):
              current_iteration_cost = state.mstate.max_gas_used - loop_gas_item.last_seen_gas_cost
              loop_gas_item.iteration_gas_cost.append(current_iteration_cost)
              
            loop_gas_item.last_seen_gas_cost = state.mstate.max_gas_used
            
            annotation.loop_gas_meter[pc] = loop_gas_item
            
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

            annotation = get_loop_gas_meter_annotation(state)
            
            for pc in annotation.loop_gas_meter.keys():
              current_global_gas_item = self.global_loop_gas_meter.get(pc, LoopGasMeterItem)
              annotation_pc_gas_item = annotation.loop_gas_meter[pc]
              
              current_global_gas_item.merge(annotation_pc_gas_item)
            
        # @symbolic_vm.laser_hook("add_world_state")
        # def world_state_filter_hook(state: GlobalState):
        #     _transaction_end(state)
            
