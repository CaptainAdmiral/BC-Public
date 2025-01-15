from typing import Protocol, runtime_checkable

@runtime_checkable
class Timestamped(Protocol):
    timestamp: float