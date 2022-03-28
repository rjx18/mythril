# from mythril.laser.ethereum.svm import LaserEVM
# from mythril.laser.plugin.interface import LaserPlugin
# from mythril.laser.plugin.builder import PluginBuilder
# from mythril.laser.plugin.signals import PluginSkipState
# from mythril.laser.plugin.plugins.plugin_annotations import (
#     GasMeterTrackerAnnotation,
#     PCGasMeter
# )
# from mythril.laser.ethereum.state.global_state import GlobalState
# from mythril.laser.ethereum.transaction.transaction_models import (
#     ContractCreationTransaction,
# )
# from mythril.exceptions import UnsatError
# from mythril.analysis import solver
# from typing import cast, List, Dict, Set
# import logging

# from mythril.laser.ethereum.instruction_data import get_opcode_gas, calculate_sha3_gas

# log = logging.getLogger(__name__)

# def get_gas_meter_annotation(state: GlobalState) -> GasMeterTrackerAnnotation:
#     """Returns a functional gas meter annotation

#     :param state: A global state object
#     """

#     annotations = cast(
#         List[GasMeterTrackerAnnotation], list(state.get_annotations(GasMeterTrackerAnnotation))
#     )

#     if len(annotations) == 0:
#         print("Annotation not found")
#         annotation = GasMeterTrackerAnnotation()
#         state.annotate(annotation)
#     else:
#         annotation = annotations[0]

#     return annotation

# class GasMeterBuilder(PluginBuilder):
#     name = "gas-meter"

#     def __call__(self, *args, **kwargs):
#         return GasMeter()

# class GasMeter(LaserPlugin):
#     """Dependency Pruner Plugin

#     For every insturction, this plugin keeps a list of storage locations that
#     are accessed (read) in the execution path containing that block. This map
#     is built up over the whole symbolic execution run.

#     After the initial build up of the map in the first transaction, blocks are
#     executed only if any of the storage locations written to in the previous
#     transaction can have an effect on that block or any of its successors.
#     """

#     def __init__(self):
#         """Creates GasMeter"""
#         self._reset()

#     def _reset(self):
#         self.gas_meter = {}

#     def initialize(self, symbolic_vm: LaserEVM) -> None:
#         """Initializes the DependencyPruner

#         :param symbolic_vm
#         """
#         self._reset()

#         @symbolic_vm.instr_hook("post", None)
#         def add_opcode_gas_hook(state: GlobalState):
#             annotation = get_gas_meter_annotation(state)
          
#             opcode = state.instruction["opcode"]
#             pc = state.instruction["address"]
            
#             gas_meter = annotation.gas_meter.get(pc, PCGasMeter())
#             gas_meter.min_opcode_gas_used += min_gas
#             gas_meter.max_opcode_gas_used += max_gas
#             state.mstate.pc_gas_meter[pc] = gas_meter
            
#             print("MY_DEBUG current max gas for pc " + str(pc) + " is " + str(state.mstate.pc_gas_meter[pc].max_opcode_gas_used))
            

#         # @symbolic_vm.post_hook("JUMP")
#         # def jump_hook(state: GlobalState):
#         #     try:
#         #         address = state.get_current_instruction()["address"]
#         #     except IndexError:
#         #         raise PluginSkipState
#         #     annotation = get_dependency_annotation(state)
#         #     annotation.path.append(address)

#         #     _check_basic_block(address, annotation)

#         # @symbolic_vm.post_hook("JUMPI")
#         # def jumpi_hook(state: GlobalState):
#         #     try:
#         #         address = state.get_current_instruction()["address"]
#         #     except IndexError:
#         #         raise PluginSkipState
#         #     annotation = get_dependency_annotation(state)
#         #     annotation.path.append(address)

#         #     _check_basic_block(address, annotation)

#         # @symbolic_vm.pre_hook("SSTORE")
#         # def sstore_hook(state: GlobalState):
#         #     annotation = get_dependency_annotation(state)

#         #     location = state.mstate.stack[-1]

#         #     self.update_sstores(annotation.path, location)
#         #     annotation.extend_storage_write_cache(self.iteration, location)

#         # @symbolic_vm.pre_hook("SLOAD")
#         # def sload_hook(state: GlobalState):
#         #     annotation = get_dependency_annotation(state)
#         #     location = state.mstate.stack[-1]

#         #     if location not in annotation.storage_loaded:
#         #         annotation.storage_loaded.add(location)

#         #     # We backwards-annotate the path here as sometimes execution never reaches a stop or return
#         #     # (and this may change in a future transaction).

#         #     self.update_sloads(annotation.path, location)
#         #     self.storage_accessed_global.add(location)

#         # @symbolic_vm.pre_hook("CALL")
#         # def call_hook(state: GlobalState):
#         #     annotation = get_dependency_annotation(state)

#         #     self.update_calls(annotation.path)
#         #     annotation.has_call = True

#         # @symbolic_vm.pre_hook("STATICCALL")
#         # def staticcall_hook(state: GlobalState):
#         #     annotation = get_dependency_annotation(state)

#         #     self.update_calls(annotation.path)
#         #     annotation.has_call = True

#         # @symbolic_vm.pre_hook("STOP")
#         # def stop_hook(state: GlobalState):
#         #     _transaction_end(state)

#         # @symbolic_vm.pre_hook("RETURN")
#         # def return_hook(state: GlobalState):
#         #     _transaction_end(state)

#         def _transaction_end(state: GlobalState) -> None:
#             """When a stop or return is reached, the storage locations read along the path are entered into
#             the dependency map for all nodes encountered in this path.

#             :param state:
#             """

#             annotation = get_dependency_annotation(state)

#             for index in annotation.storage_loaded:
#                 self.update_sloads(annotation.path, index)

#             for index in annotation.storage_written:
#                 self.update_sstores(annotation.path, index)

#             if annotation.has_call:
#                 self.update_calls(annotation.path)

#         def _check_basic_block(address: int, annotation: DependencyAnnotation):
#             """This method is where the actual pruning happens.

#             :param address: Start address (bytecode offset) of the block
#             :param annotation:
#             """

#             # Don't skip any blocks in the contract creation transaction
#             if self.iteration < 2:
#                 return

#             # Don't skip newly discovered blocks
#             if address not in annotation.blocks_seen:
#                 annotation.blocks_seen.add(address)
#                 return

#             if self.wanna_execute(address, annotation):
#                 return
#             else:
#                 log.debug(
#                     "Skipping state: Storage slots {} not read in block at address {}, function".format(
#                         annotation.get_storage_write_cache(self.iteration - 1), address
#                     )
#                 )

#                 raise PluginSkipState

#         @symbolic_vm.laser_hook("add_world_state")
#         def world_state_filter_hook(state: GlobalState):

#             if isinstance(state.current_transaction, ContractCreationTransaction):
#                 # Reset iteration variable
#                 self.iteration = 0
#                 return

#             world_state_annotation = get_ws_dependency_annotation(state)
#             annotation = get_dependency_annotation(state)

#             # Reset the state annotation except for storage written which is carried on to
#             # the next transaction

#             annotation.path = [0]
#             annotation.storage_loaded = set()

#             world_state_annotation.annotations_stack.append(annotation)
