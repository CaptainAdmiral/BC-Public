from typing import TYPE_CHECKING
from uuid import UUID

from protocol.credit.credit_types import FundTypeEnum, FundTypes
from protocol.dialogue.packets import TrackedFundPacket
from protocol.protocols.common_types import VerificationNodeData
from settings import GAS_AMOUNT

if TYPE_CHECKING:
    from protocol.credit.credit_types import FundWithdrawal, Receipt, Stake


class TrackedFund:

    def __init__(self, details: FundTypes):
        self.id = details.id
        self.details = details
        self.withdrawals: list["Receipt"] = []
        self.reservations: list["Stake"] = []

    @classmethod
    def from_packet(cls, packet: TrackedFundPacket):
        tracked_fund = TrackedFund(packet.details)
        tracked_fund.withdrawals.extend(packet.withdrawals)
        tracked_fund.reservations.extend(packet.reservations)

    def to_packet(self):
        return TrackedFundPacket(
            self.details, tuple(self.withdrawals), tuple(self.reservations)
        )

    @property
    def available(self):
        if self.details.fund_type == FundTypeEnum.GAS:
            return self.details.amount - sum(
                receipt.contract.amount for receipt in self.withdrawals
            )
        else:
            return (
                self.details.amount
                - sum(
                    receipt.contract.amount + GAS_AMOUNT for receipt in self.withdrawals
                )
                - GAS_AMOUNT
            )

    @property
    def reserved(self):
        return sum(reservation.amount for reservation in self.reservations)

    @property
    def remaining(self):
        return self.available + self.reserved

    def total_credit(self):
        return self.details.amount - sum(
            receipt.contract.amount for receipt in self.withdrawals
        )

    def withdraw_credit(self, withdrawal: "FundWithdrawal", receipt: "Receipt"):
        assert withdrawal.amount <= self.available
        self.withdrawals.append(receipt)

    def reserve_credit(self, stake: "Stake"):
        amount = stake.amount
        assert amount <= self.available

    def release_credit(self, stake_id: UUID):
        self.reservations = list(
            filter(lambda res: res.uuid == stake_id, self.reservations)
        )

    def update_after_rollover(
        self, new_witnesses: tuple[VerificationNodeData, ...], new_timestamp: float
    ):
        """Updates the receipt for this fund with the correct information after a rollover"""
        self.details = self.details.update_witnesses(new_witnesses, new_timestamp)

    def is_expired(self):
        return self.details.is_expired()

    def validate_expiry(self):
        self.details.validate_expiry()

    def __hash__(self):
        return hash(self.details)
