from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated

from pydantic import Discriminator

from crypto.signature import Signed
from protocol.credit.credit_types import FundTypes, get_fund_type
from protocol.credit.credit_types import Receipt, Stake
from protocol.protocols.common_types import VerificationNodeData


@dataclass(frozen=True)
class LatestChecksumPacket:
    checksum: str | None
    cutoff: float | None = None


@dataclass(frozen=True)
class Nullable[T]:
    val: T | None


@dataclass(frozen=True)
class TrackedFundPacket:
    details: Annotated[FundTypes, Discriminator(get_fund_type)]
    withdrawals: tuple[Receipt, ...]
    reservations: tuple[Stake, ...]

    @property
    def id(self):
        return self.details.id


@dataclass(frozen=True)
class RolloverPacket:
    signed_fund: Signed[TrackedFundPacket]
    new_witnesses: tuple[VerificationNodeData, ...]
    witness_selection_time: float