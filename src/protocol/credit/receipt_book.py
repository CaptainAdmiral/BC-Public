from protocol.credit.tracked_fund import TrackedFund
from protocol.credit.credit_types import FundWithdrawal, Receipt

class ReceiptBook:
    
    def __init__(self) -> None:
        self._tracked_funds: dict[str, TrackedFund] = {}

    def update_credit(self, withdrawal: FundWithdrawal, receipt: Receipt):
        '''Updates the internally tracked credit based on the receipt'''

        assert(withdrawal in receipt.contract.funds)
        
        tracked_fund = self._tracked_funds[withdrawal.receipt_id]
        tracked_fund.withdraw_credit(withdrawal, receipt)

    def add(self, receipt: Receipt):
        assert(receipt not in self._tracked_funds)
        self._tracked_funds[receipt.id] = TrackedFund(receipt)

    def get(self, key: Receipt | str):
        if isinstance(key, Receipt):
            return self._tracked_funds[key.id]
        return self._tracked_funds[key]
    
    def __getitem__(self, key: Receipt | str) -> TrackedFund:
        return self.get(key)
    
    def __contains__(self, item: Receipt | str):
        if isinstance(item, Receipt):
            return item.id in self._tracked_funds
        return item in self._tracked_funds