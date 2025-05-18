from typing import Protocol, runtime_checkable

@runtime_checkable
class Timestamped(Protocol):

    @property
    def timestamp(self) -> float:
        ...