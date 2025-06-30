import random
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, replace
from enum import StrEnum, auto
from functools import cache
import statistics
from typing import TYPE_CHECKING, Annotated, Any, Literal
from uuid import UUID

from pydantic import Discriminator, Tag

from crypto.signature import ManagedSignable, Signed, TimestampedSignature
from crypto.util import to_sha256
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.util.rng_seed import (
    RNGSeed,
    RNGSeedTypes,
    get_rng_type,
)
from protocol.dialogue.util.witness_selection_util import (
    validate_missing_events,
    validate_selected_witnesses,
)
from protocol.protocols.common_types import VerificationNodeData
from settings import (
    GAS_AMOUNT,
    NODE_0_PUBLIC_KEY,
    ROLLOVER_PERIOD,
    STAKE_AMOUNT,
    TIME_TO_CONSISTENCY,
)
from timeline import cur_time

if TYPE_CHECKING:
    from protocol.protocols.std_protocol.std_protocol import StdProtocol
    from protocol.verification_net.verification_net_timeline import (
        VerificationNetTimeline,
    )


class ContractType(StrEnum):
    TRANSACTION = auto()
    STAKE = auto()


@dataclass(frozen=True)
class Contract(ManagedSignable):
    uuid: UUID
    contract_type: ContractType


@dataclass(frozen=True)
class FundWithdrawal(ManagedSignable):
    fund_id: str
    fund_timestamp: float
    rng_seed: Annotated[RNGSeedTypes, Discriminator(get_rng_type)]
    witnesses: tuple[VerificationNodeData, ...]
    missing_event_ids: tuple[str, ...]
    amount: int

    def signature_content(self) -> Any:
        return (
            self.fund_id,
            self.amount,
            self.fund_timestamp,
            self.rng_seed,
        )

    def witnessed_by(self, public_key: str) -> bool:
        for witness in self.witnesses:
            if witness.public_key == public_key:
                return True
        return False

    def validate_selected_witnesses(self, vnt: "VerificationNetTimeline"):
        checksum = vnt.get_latest_checksum(self.fund_timestamp - TIME_TO_CONSISTENCY)
        seed = self.rng_seed
        if checksum != seed.checksum:
            raise DialogueException(
                f"Invalid RNG seed, checksum {seed.checksum} does not match for timestamp {self.fund_timestamp}"
            )
        validate_selected_witnesses(
            vnt=vnt,
            selected_nodes=set(self.witnesses),
            time_of_selection=self.fund_timestamp,
            seed=seed,
            missing_event_ids=set(self.missing_event_ids),
        )

    def validate_missing_events(self, vnt: "VerificationNetTimeline"):
        events = (vnt.event_from_id(event_id) for event_id in self.missing_event_ids)
        validate_missing_events(events, self.fund_timestamp)


@dataclass(frozen=True)
class Transaction(Contract):
    uuid: UUID
    contract_type: Literal[ContractType.TRANSACTION]
    payer_address: int
    payer_public_key: str
    payee_address: int
    payee_public_key: str
    amount: int
    funds: tuple[FundWithdrawal, ...]
    timestamp: float

    def signature_content(self) -> Any:
        return (
            self.uuid,
            self.contract_type,
            self.payer_public_key,
            self.payee_public_key,
            self.amount,
            [fund.signature_content() for fund in self.funds],
            self.timestamp,
        )

    def validate_funds(self, protocol: "StdProtocol"):
        """Validates the funds for this transaction and raises and exception if not"""

        if self.payer_public_key == NODE_0_PUBLIC_KEY:
            return

        if self.amount != sum(fund.amount for fund in self.funds):
            raise ValueError("Invalid transaction, not enough funds to cover payment")

        for fund in self.funds:
            fund.validate_missing_events(protocol.verification_net_timeline)
            fund.validate_selected_witnesses(protocol.verification_net_timeline)


class FundTypeEnum(StrEnum):
    RECEIPT = auto()
    GAS = auto()
    CLAIM_STAKE = auto()


@dataclass(frozen=True)
class Fund(ABC):
    fund_type: FundTypeEnum
    rng_seed: RNGSeed
    witnesses: tuple[VerificationNodeData, ...]
    timestamp: float

    @property
    @cache
    @abstractmethod
    def id(self) -> str: ...

    @abstractmethod
    def __hash__(self):
        return super().__hash__()

    @property
    @abstractmethod
    def amount(self) -> int: ...

    def update_witnesses(
        self, new_witnesses: tuple[VerificationNodeData, ...], new_timestamp: float
    ):
        return replace(self, witnesses=new_witnesses, timestamp=new_timestamp)

    def validate_selected_witnesses(self, protocol: "StdProtocol"):
        """Convenience wrapper for util.validate_selected_witnesses.
        Validates if the selected witnesses are correct for this contract and raises an exception if not
        """
        ...

    def witnessed_by(self, public_key: str) -> bool:
        for witness in self.witnesses:
            if witness.public_key == public_key:
                return True
        return False

    def is_expired(self):
        return cur_time() > self.timestamp + ROLLOVER_PERIOD

    def validate_expiry(self):
        if self.is_expired():
            raise DialogueException(f"Fund Expired: {self.id}")


@dataclass(frozen=True)
class Receipt(ManagedSignable, Fund, Signed[Transaction]):
    fund_type: Literal[FundTypeEnum.RECEIPT]
    message: Transaction
    rng_seed: Annotated[RNGSeedTypes, Discriminator(get_rng_type)]
    witnesses: tuple[VerificationNodeData, ...]
    timestamp: float

    @property
    @cache
    def id(self):
        return to_sha256((self.fund_type, self.message))

    def __hash__(self):
        return hash((self.fund_type, self.message))

    @property
    def contract(self):
        return self.message

    @property
    def amount(self):
        return self.message.amount

    def signature_content(self) -> Any:
        return self.message.signature_content()

    def validate_selected_witnesses(self, protocol: "StdProtocol"):
        validate_selected_witnesses(
            vnt=protocol.verification_net_timeline,
            selected_nodes=set(self.witnesses),
            time_of_selection=self.timestamp,
            seed=self.rng_seed,
        )


@dataclass(frozen=True)
class GasFund(Fund):
    fund_type: Literal[FundTypeEnum.GAS]
    held_fund: Fund
    withdrawals: tuple[Receipt, ...]
    rng_seed: Annotated[RNGSeedTypes, Discriminator(get_rng_type)]
    witnesses: tuple[VerificationNodeData, ...]
    fund_owner_pk: str
    timestamp: float

    @property
    @cache
    def id(self):
        return to_sha256((self.fund_type, self.held_fund.id, self.fund_owner_pk))

    def __hash__(self):
        return hash((self.fund_type, self.held_fund.id, self.fund_owner_pk))

    @property
    @cache
    def amount(self):
        rng = random.Random(self.rng_seed.seed_bytes())

        total = 0
        for withdrawal in self.withdrawals:
            signatories = withdrawal.signatories & set(
                witness.public_key for witness in self.witnesses
            )
            n_sigs = len(signatories)
            total += GAS_AMOUNT // n_sigs

            rem = GAS_AMOUNT % n_sigs
            if rem:
                sig_list = list(signatories)
                rng.shuffle(sig_list)
                if self.fund_owner_pk in sig_list[:rem]:
                    total += 1
        return total

    def validate_selected_witnesses(self, protocol: "StdProtocol"):
        validate_selected_witnesses(
            vnt=protocol.verification_net_timeline,
            selected_nodes=set(self.witnesses),
            time_of_selection=self.timestamp,
            seed=self.rng_seed,
        )


@dataclass(frozen=True)
class ClaimedStake:
    original_fund: Fund
    withdrawals: tuple[Receipt, ...]
    fund_owner_pk: str

    @cache
    def get_bad_witnesses(self):
        stake_losers: list[VerificationNodeData] = []
        original_amount = self.original_fund.amount
        tracked_withdrawals: defaultdict[str, int] = defaultdict(int)
        for withdrawal in self.withdrawals:
            for sig in withdrawal.signatories:
                tracked_withdrawals[sig] += withdrawal.amount

        for pk, tracked_amount in tracked_withdrawals.items():
            if tracked_amount > original_amount:
                bad_witness = next(
                    witness for withdrawal in self.withdrawals for witness in withdrawal.witnesses if witness.public_key == pk
                )
                stake_losers.append(bad_witness)
        return stake_losers

    @property
    @cache
    def amount(self):
        return len(self.get_bad_witnesses()) * STAKE_AMOUNT

    def validate(self, protocol: "StdProtocol"):
        if not self.get_bad_witnesses():
            raise DialogueException("No bad witnesses in stake claim")
        for receipt in self.withdrawals:
            receipt.validate_selected_witnesses(protocol)
            receipt.validate_signatures()


@dataclass(frozen=True)
class TimestampedStakeClaim:
    stake: ClaimedStake
    timestamp: float


@dataclass(frozen=True)
class ClaimedStakeFund(Fund):
    claimed_stake: ClaimedStake
    timestamped_signatures: tuple[TimestampedSignature, ...]
    fund_type: Literal[FundTypeEnum.CLAIM_STAKE]
    rng_seed: Annotated[RNGSeedTypes, Discriminator(get_rng_type)]
    witnesses: tuple[VerificationNodeData, ...]
    timestamp: float
    
    def __post_init__(self):
        if self.timestamp is not None:
            raise ValueError("timestamp is computed automatically, expected timestamp=None")

        timestamp: float = statistics.median(ts.timestamp for ts in self.timestamped_signatures)
        object.__setattr__(self, 'timestamp', timestamp)

    @property
    @cache
    def id(self):
        return to_sha256((self.fund_type, self.claimed_stake.original_fund.id))

    def __hash__(self):
        return hash((self.fund_type, self.claimed_stake.original_fund.id))

    @property
    def amount(self) -> int:
        return self.claimed_stake.amount

    def validate(self, protocol: "StdProtocol"):
        self.claimed_stake.validate(protocol)
        for ts_sig in self.timestamped_signatures:
            ts_sig.signature.validate(TimestampedStakeClaim(self.claimed_stake, ts_sig.timestamp))

    def validate_selected_witnesses(self, protocol: "StdProtocol"):
        validate_selected_witnesses(
            vnt=protocol.verification_net_timeline,
            selected_nodes=set(self.witnesses),
            time_of_selection=self.timestamp,
            seed=self.rng_seed,
        )

def get_fund_type(v: Any) -> str:
    if isinstance(v, dict):
        return v["fund_type"]
    return getattr(v, "fund_type")


FundTypes = (
    Annotated[Receipt, Tag(FundTypeEnum.RECEIPT)]
    | Annotated[GasFund, Tag(FundTypeEnum.GAS)]
    | Annotated[ClaimedStakeFund, Tag(FundTypeEnum.CLAIM_STAKE)]
)


@dataclass(frozen=True)
class Stake(Contract):
    uuid: UUID
    contract_type: Literal[ContractType.STAKE]
    address: int
    public_key: str
    amount: int
    funds: tuple[FundWithdrawal, ...]
    timestamp: float

    def signature_content(self) -> Any:
        return (
            self.uuid,
            self.contract_type,
            self.public_key,
            self.amount,
            [fund.signature_content() for fund in self.funds],
            self.timestamp,
        )

    def validate_funds(self, vnt: "VerificationNetTimeline", cur_time: float):
        """Validates the funds for this transaction and raises and exception if not"""

        if self.public_key == NODE_0_PUBLIC_KEY:
            return

        if self.amount != STAKE_AMOUNT:
            raise ValueError("Invalid stake, wrong amount")

        if self.amount != sum(fund.amount for fund in self.funds):
            raise ValueError("Invalid stake, not enough funds to cover payment")

        for fund in self.funds:
            fund.validate_missing_events(vnt)
            fund.validate_selected_witnesses(vnt)

    def get_node(self):
        "Get's the node data for the node joining the verification network with this stake"

        return VerificationNodeData(
            address=self.address, public_key=self.public_key, timestamp=self.timestamp
        )
