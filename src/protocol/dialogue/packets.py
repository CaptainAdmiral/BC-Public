from dataclasses import dataclass

@dataclass(frozen=True)
class LatestChecksumPacket:
    checksum: str | None
    cutoff: float | None = None

@dataclass(frozen=True)
class Nullable[T]:
    val: T | None 