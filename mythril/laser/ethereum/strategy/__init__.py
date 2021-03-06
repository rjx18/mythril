from abc import ABC, abstractmethod
from typing import List
from mythril.laser.ethereum.state.global_state import GlobalState


class BasicSearchStrategy(ABC):
    """"""

    __slots__ = "work_list", "max_depth", "skip_state_hooks"

    def __init__(self, work_list, max_depth, skip_state_hooks):
        self.work_list = work_list  # type: List[GlobalState]
        self.max_depth = max_depth
        self.skip_state_hooks = skip_state_hooks

    def __iter__(self):
        return self

    @abstractmethod
    def get_strategic_global_state(self):
        """"""
        raise NotImplementedError("Must be implemented by a subclass")

    def __next__(self):
        try:
            global_state = self.get_strategic_global_state()
            if global_state.mstate.depth >= self.max_depth:
                for hook in self.skip_state_hooks:
                    hook(global_state)
                return self.__next__()
            return global_state
        except IndexError:
            raise StopIteration
