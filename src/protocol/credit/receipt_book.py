from uuid import UUID
from protocol.credit.tracked_fund import TrackedFund
from protocol.credit.credit_types import FundWithdrawal, Receipt

class ReceiptBook:
    
    def __init__(self) -> None:
        self._tracked_funds: dict[UUID, TrackedFund]

    def update_credit(self, withdrawal: FundWithdrawal, receipt: Receipt):
        '''Updates the internally tracked credit based on the receipt'''

        assert(withdrawal in receipt.contract.funds)
        
        tracked_fund = self._tracked_funds[withdrawal.receipt_id]
        tracked_fund.log_withdrawal(withdrawal, receipt)

    def reserve_credit(self, details: ...):
        '''Updates the internally tracked credit based on the ...'''
        ...

    def release_credit(self, details: ...):
        '''Updates the internally tracked credit based on the ...'''
        ...

    def add(self, receipt: Receipt):
        assert(receipt not in self._tracked_funds)
        self._tracked_funds[receipt.uuid] = TrackedFund(receipt)

    def get(self, key: Receipt | UUID):
        if isinstance(key, Receipt):
            return self._tracked_funds[key.uuid]
        return self._tracked_funds[key]
    
    def __getitem__(self, key: Receipt | UUID) -> TrackedFund:
        return self.get(key)
    
    def __contains__(self, item: Receipt | UUID):
        if isinstance(item, Receipt):
            return item.uuid in self._tracked_funds
        return item in self._tracked_funds