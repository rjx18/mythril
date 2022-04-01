from mythril.laser.ethereum.state.annotation import (
    StateAnnotation,
    MergeableStateAnnotation,
)

from copy import copy
from typing import Dict, List, Set
import logging

import json

log = logging.getLogger(__name__)


class MutationAnnotation(StateAnnotation):
    """Mutation Annotation

    This is the annotation used by the MutationPruner plugin to record mutations
    """

    def __init__(self):
        pass

    @property
    def persist_over_calls(self) -> bool:
        return True

class GasMeterItem:
    """
    PCGasMeter represents current machine gas meter statistics.
    """
    def __init__(self, min_opcode_gas_used=0, max_opcode_gas_used=0, mem_gas_used=0, min_storage_gas_used=0, max_storage_gas_used=0, num_invocations=0, num_tx=1):
        self.min_opcode_gas_used = min_opcode_gas_used
        self.max_opcode_gas_used = max_opcode_gas_used
        self.mem_gas_used = mem_gas_used
        self.min_storage_gas_used = min_storage_gas_used
        self.max_storage_gas_used = max_storage_gas_used
        self.num_invocations = num_invocations
        
        self.num_tx = num_tx

    def __copy__(self):
        return GasMeterItem(
            min_opcode_gas_used=self.min_opcode_gas_used, 
            max_opcode_gas_used=self.max_opcode_gas_used, 
            mem_gas_used=self.mem_gas_used,
            min_storage_gas_used=self.min_storage_gas_used,
            max_storage_gas_used=self.max_storage_gas_used,
            num_invocations=self.num_invocations
        )
        
    def merge(self, other: "GasMeterItem"):
        self.min_opcode_gas_used += other.min_opcode_gas_used
        self.max_opcode_gas_used += other.max_opcode_gas_used
        self.mem_gas_used += other.mem_gas_used
        self.min_storage_gas_used += other.min_storage_gas_used
        self.max_storage_gas_used += other.max_storage_gas_used
        
        self.num_invocations += other.num_invocations
        self.num_tx += other.num_tx

    def __dict__(self):
        total_max_opcode_gas = (self.max_opcode_gas_used + self.max_storage_gas_used)
        mean_max_opcode_gas = total_max_opcode_gas / self.num_tx
    
        total_min_opcode_gas = (self.min_opcode_gas_used + self.min_storage_gas_used)
        mean_min_opcode_gas = total_min_opcode_gas / self.num_tx
        
        total_mem_gas = self.mem_gas_used
        mean_mem_gas = total_mem_gas / self.num_tx
        
        mean_wc_gas = mean_max_opcode_gas + mean_mem_gas      
        
        return dict(
            numTx=self.num_tx,
            totalMaxOpcodeGas=total_max_opcode_gas,
            meanMaxOpcodeGas=mean_max_opcode_gas,
            totalMinOpcodeGas=total_min_opcode_gas,
            meanMinOpcodeGas=mean_min_opcode_gas,
            totalMemGas=total_mem_gas,
            meanMemGas=mean_mem_gas,
            meanWcGas=mean_wc_gas
        )

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__())

class GasMeterTrackerAnnotation(StateAnnotation):
    """Gas Meter Tracker Annotation

    This annotation tracks gas usage per PC.
    """

    def __init__(self):
        self.last_seen_max_gas = 0
        self.last_seen_min_gas = 0
        self.last_seen_mem_gas = 0
        self.last_seen_max_storage_gas = 0
        self.last_seen_min_storage_gas = 0
        
        self.curr_tx_seen_pc = set()
        
        self.gas_meter = {}

    def __copy__(self):
        result = GasMeterTrackerAnnotation()
        result.gas_meter = copy(self.gas_meter)
        
        result.last_seen_max_gas = self.last_seen_max_gas
        result.last_seen_min_gas = self.last_seen_min_gas
        result.last_seen_mem_gas = self.last_seen_mem_gas
        result.last_seen_max_storage_gas = self.last_seen_max_storage_gas
        result.last_seen_min_storage_gas = self.last_seen_min_storage_gas
        
        result.curr_tx_seen_pc = copy(self.curr_tx_seen_pc)
        
        return result

class LoopGasMeterItem:
    """
    PCGasMeter represents current machine gas meter statistics.
    """
    def __init__(self, last_seen_gas_cost=None, iteration_gas_cost=None):
        self.last_seen_gas_cost = last_seen_gas_cost
        self.iteration_gas_cost = iteration_gas_cost or []

    def __copy__(self):
        return LoopGasMeterItem(
            last_seen_gas_cost=self.last_seen_gas_cost, 
            iteration_gas_cost=copy(self.iteration_gas_cost), 
        )
        
    def merge(self, other: "LoopGasMeterItem"):
        self.iteration_gas_cost = self.iteration_gas_cost + other.iteration_gas_cost

class LoopGasMeterAnnotation(StateAnnotation):
    """Function Gas Meter Annotation

    This annotation tracks current function.
    """
    
    def __init__(self):
        self.loop_gas_meter = {}
        
    def __copy__(self):
        result = LoopGasMeterAnnotation()
        result.loop_gas_meter = copy(self.loop_gas_meter)
        return result

    

class FunctionTrackerAnnotation(MergeableStateAnnotation):
    """Function Gas Meter Annotation

    This annotation tracks current function.
    """

    def __init__(self):
        self.current_function = None  # type: str or None
        self.last_seen_function = None

    def __copy__(self):
        result = FunctionTrackerAnnotation()
        result.current_function = self.current_function
        result.last_seen_function = self.last_seen_function
        return result

    def check_merge_annotation(self, other: "FunctionTrackerAnnotation"):
        if not isinstance(other, FunctionTrackerAnnotation):
            raise TypeError("Expected an instance of FunctionTrackerAnnotation")
        return self.current_function == other.current_function and self.last_seen_function == other.last_seen_function

    def merge_annotation(self, other: "FunctionTrackerAnnotation"):
        merged_annotation = FunctionTrackerAnnotation()
        merged_annotation.current_function = self.current_function
        merged_annotation.last_seen_function = self.last_seen_function
        return merged_annotation

class DependencyAnnotation(MergeableStateAnnotation):
    """Dependency Annotation

    This annotation tracks read and write access to the state during each transaction.
    """

    def __init__(self):
        self.storage_loaded = set()  # type: Set
        self.storage_written = {}  # type: Dict[int, Set]
        self.has_call = False  # type: bool
        self.path = [0]  # type: List
        self.blocks_seen = set()  # type: Set[int]

    def __copy__(self):
        result = DependencyAnnotation()
        result.storage_loaded = copy(self.storage_loaded)
        result.storage_written = copy(self.storage_written)
        result.has_call = self.has_call
        result.path = copy(self.path)
        result.blocks_seen = copy(self.blocks_seen)
        return result

    def get_storage_write_cache(self, iteration: int):
        return self.storage_written.get(iteration, set())

    def extend_storage_write_cache(self, iteration: int, value: object):
        if iteration not in self.storage_written:
            self.storage_written[iteration] = set()
        self.storage_written[iteration].add(value)

    def check_merge_annotation(self, other: "DependencyAnnotation"):
        if not isinstance(other, DependencyAnnotation):
            raise TypeError("Expected an instance of DependencyAnnotation")
        return self.has_call == other.has_call and self.path == other.path

    def merge_annotation(self, other: "DependencyAnnotation"):
        merged_annotation = DependencyAnnotation()
        merged_annotation.blocks_seen = self.blocks_seen.union(other.blocks_seen)
        merged_annotation.has_call = self.has_call
        merged_annotation.path = copy(self.path)
        merged_annotation.storage_loaded = self.storage_loaded.union(
            other.storage_loaded
        )
        keys = set(
            list(other.storage_written.keys()) + list(self.storage_written.keys())
        )
        for key in keys:
            other_set = other.storage_written.get(key, set())
            merged_annotation.storage_written[key] = self.storage_written.get(
                key, set()
            ).union(other_set)
        return merged_annotation


class WSDependencyAnnotation(MergeableStateAnnotation):
    """Dependency Annotation for World state

    This  world state annotation maintains a stack of state annotations.
    It is used to transfer individual state annotations from one transaction to the next.
    """

    def __init__(self):
        self.annotations_stack: List[DependencyAnnotation] = []

    def __copy__(self):
        result = WSDependencyAnnotation()
        result.annotations_stack = copy(self.annotations_stack)
        return result

    def check_merge_annotation(self, annotation: "WSDependencyAnnotation") -> bool:
        if len(self.annotations_stack) != len(annotation.annotations_stack):
            # We can only merge worldstate annotations that have seen an equal amount of transactions
            # since the beginning of symbolic execution
            return False
        for a1, a2 in zip(self.annotations_stack, annotation.annotations_stack):
            if a1 == a2:
                continue
            if (
                isinstance(a1, MergeableStateAnnotation)
                and isinstance(a2, MergeableStateAnnotation)
                and a1.check_merge_annotation(a2) is True
            ):
                continue
            log.debug("Aborting merge between annotations {} and {}".format(a1, a2))
            return False

        return True

    def merge_annotation(
        self, annotation: "WSDependencyAnnotation"
    ) -> "WSDependencyAnnotation":
        merged_annotation = WSDependencyAnnotation()
        for a1, a2 in zip(self.annotations_stack, annotation.annotations_stack):
            if a1 == a2:
                merged_annotation.annotations_stack.append(copy(a1))
            merged_annotation.annotations_stack.append(a1.merge_annotation(a2))
        return merged_annotation
