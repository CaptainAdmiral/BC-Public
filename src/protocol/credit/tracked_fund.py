from uuid import UUID
from protocol.credit.credit_types import FundWithdrawal, Receipt, Stake

class TrackedFund:

    def __init__(self, receipt: Receipt):
        self.receipt = receipt
        self.withdrawals: list[Receipt] = []
        self.reservations: list[Stake] = []

    @property
    def available(self):
        return self.receipt.contract.amount - sum(receipt.contract.amount for receipt in self.withdrawals)
    
    @property
    def reserved(self):
        return sum(reservation.amount for reservation in self.reservations)

    @property
    def remaining(self):
        return self.available + self.reserved

    def withdraw_credit(self, withdrawal: FundWithdrawal, receipt: Receipt):
        assert(withdrawal.amount <= self.available)
        self.withdrawals.append(receipt)

    def reserve_credit(self, stake: Stake):
        amount = stake.amount
        assert(amount <= self.available)

    def release_credit(self, stake_id: UUID):
        self.reservations = list(filter(lambda res: res.uuid == stake_id, self.reservations))

    def __hash__(self):
        return hash(self.receipt)