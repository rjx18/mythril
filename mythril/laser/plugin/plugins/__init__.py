""" Plugin implementations

This module contains the implementation of some features

- benchmarking
- pruning
"""
from mythril.laser.plugin.plugins.benchmark import BenchmarkPluginBuilder
from mythril.laser.plugin.plugins.coverage.coverage_plugin import CoveragePluginBuilder
from mythril.laser.plugin.plugins.dependency_pruner import DependencyPrunerBuilder
from mythril.laser.plugin.plugins.mutation_pruner import MutationPrunerBuilder
from mythril.laser.plugin.plugins.call_depth_limiter import CallDepthLimitBuilder
from mythril.laser.plugin.plugins.instruction_profiler import InstructionProfilerBuilder
from mythril.laser.plugin.plugins.function_tracker import FunctionTrackerBuilder 
from mythril.laser.plugin.plugins.loop_gas_meter import LoopGasMeterBuilder
from mythril.laser.plugin.plugins.gas_meter import GasMeterBuilder
from mythril.laser.plugin.plugins.loop_mutation_detector import LoopMutationDetectorBuilder