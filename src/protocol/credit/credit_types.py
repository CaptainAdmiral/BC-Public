from abc import ABC
from dataclasses import dataclass
from enum import StrEnum, auto
from functools import cache
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from crypto.signature import Signed
from crypto.util import to_sha256
from protocol.dialogue.util.rng_seed import RNGSeed, WitnessSelectionRNGData
from protocol.dialogue.util.witness_selection_util import (
    validate_missing_events,
    validate_selected_witnesses,
)
from protocol.protocols.common_types import VerificationNodeData
from settings import NODE_0_PUBLIC_KEY, STAKE_AMOUNT

if TYPE_CHECKING:
    from protocol.protocols.std_protocol.std_protocol import StdProtocol
    from protocol.verification_net.verification_net_timeline import (
        VerificationNetTimeline,
    )


class ContractType(StrEnum):
    TRANSACTION = auto()
    STAKE = auto()


@dataclass(frozen=True)
class Contract(ABC):
    uuid: UUID
    contract_type: ContractType


@dataclass(frozen=True)
class FundWithdrawal:
    receipt_id: str
    rng_seed: WitnessSelectionRNGData
    witnesses: tuple[VerificationNodeData, ...]
    missing_event_ids: tuple[str, ...]
    amount: int

    def witnessed_by(self, public_key: str) -> bool:
        for witness in self.witnesses:
            if witness.public_key == public_key:
                return True
        return False

    def validate_selected_witnesses(self, vnt: "VerificationNetTimeline"):
        seed = RNGSeed.from_dataclass(self.rng_seed, vnt)
        validate_selected_witnesses(
            vnt=vnt,
            selected_nodes=set(self.witnesses),
            cutoff=self.rng_seed.timestamp,
            seed=seed,
            missing_event_ids=set(self.missing_event_ids),
        )

    def validate_missing_events(self, protocol: "StdProtocol"):
        events = (
            protocol.verification_net_timeline.event_from_id(event_id)
            for event_id in self.missing_event_ids
        )
        validate_missing_events(events, self.rng_seed.timestamp)


@dataclass(frozen=True)
class Transaction(Contract):
    contract_type: Literal[ContractType.TRANSACTION]
    payer_address: int
    payer_public_key: str
    payee_address: int
    payee_public_key: str
    amount: int
    funds: tuple[FundWithdrawal, ...]
    witnesses: tuple[VerificationNodeData, ...]
    timestamp: float

    def validate_selected_witnesses(self, protocol: "StdProtocol"):
        """Convenience wrapper for util.validate_selected_witnesses.
        Validates if the selected witnesses are correct for this contract and raises an exception if not
        """
        checksum = protocol.verification_net_timeline.get_latest_checksum(
            self.timestamp
        )
        seed = RNGSeed(
            checksum=checksum,
            payee_public_key=self.payee_public_key,
            payer_public_key=self.payer_public_key,
        )
        validate_selected_witnesses(
            vnt=protocol.verification_net_timeline,
            selected_nodes=set(self.witnesses),
            cutoff=self.timestamp,
            seed=seed,
        )

    def validate_funds(self, protocol: "StdProtocol"):
        """Validates the funds for this transaction and raises and exception if not"""

        if self.payer_public_key == NODE_0_PUBLIC_KEY:
            return

        if self.amount != sum(fund.amount for fund in self.funds):
            raise ValueError("Invalid transaction, not enough funds to cover payment")

        for fund in self.funds:
            fund.validate_missing_events(protocol)
            fund.validate_selected_witnesses(protocol.verification_net_timeline)

    def witnessed_by(self, public_key: str) -> bool:
        for witness in self.witnesses:
            if witness.public_key == public_key:
                return True
        return False


@dataclass(frozen=True)
class Receipt(Signed[Transaction]):
    message: Transaction

    @property
    def contract(self):
        return self.message

    @property
    @cache
    def id(self):
        return to_sha256(self.message)

    def __hash__(self):
        return hash(self.message)


@dataclass(frozen=True)
class Stake(Contract):
    uuid: UUID
    contract_type: Literal[ContractType.STAKE]
    address: int
    public_key: str
    amount: int
    funds: tuple[FundWithdrawal, ...]
    timestamp: float

    def validate_funds(self, vnt: "VerificationNetTimeline"):
        """Validates the funds for this transaction and raises and exception if not"""

        if self.public_key == NODE_0_PUBLIC_KEY:
            return

        if self.amount != STAKE_AMOUNT:
            raise ValueError("Invalid stake, wrong amount")

        if self.amount != sum(fund.amount for fund in self.funds):
            raise ValueError("Invalid stake, not enough funds to cover payment")

        for fund in self.funds:
            events = (
                vnt.event_from_id(event_id) for event_id in fund.missing_event_ids
            )
            validate_missing_events(events, fund.rng_seed.timestamp)
            fund.validate_selected_witnesses(vnt)

    def get_node(self):
        "Get's the node data for the node joining the verification network with this stake"

        return VerificationNodeData(
            address=self.address, public_key=self.public_key, timestamp=self.timestamp
        )
