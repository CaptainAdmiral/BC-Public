from protocol.credit.credit_types import FundWithdrawal, Receipt

class TrackedFund:

    def __init__(self, receipt: Receipt):
        self.receipt = receipt
        self._available = receipt.contract.amount
        self._reserved = 0
        self.withdrawals: list[Receipt] = []

    @property
    def available(self):
        return self._available
    
    @property
    def reserved(self):
        return self._reserved

    @property
    def remaining(self):
        return self._available + self._reserved

    def log_withdrawal(self, withdrawal: FundWithdrawal, receipt: Receipt):
        assert(withdrawal.amount <= self._available)
        self.withdrawals.append(receipt)
        self._available -= withdrawal.amount

    def reserve_credit(self, amount: int):
        assert(amount <= self._available)
        self._available -= amount
        self._reserved += amount

    def unreserve_credit(self, amount: int):
        assert(amount <= self._reserved)
        self._reserved -= amount
        self._available += amount

    def __hash__(self):
        return hash(self.receipt)