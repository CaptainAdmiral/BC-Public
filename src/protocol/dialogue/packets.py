from dataclasses import dataclass

@dataclass(frozen=True)
class LatestChecksum:
    checksum: str | None
    cutoff: float | None = None