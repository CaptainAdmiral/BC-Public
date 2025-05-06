from protocol.credit.tracked_fund import TrackedFund
from protocol.credit.credit_types import FundWithdrawal, Receipt

class Wallet:
    
    def __init__(self, address) -> None:
        self.address = address
        self._funds: list[TrackedFund] = []
        '''Sorted list of active transaction receipts into the account by amount (ascending)'''
        self._fund_dict: dict[Receipt, TrackedFund] = {}
        self._balance = 0

    def find_funds(self, amount: int) -> list[FundWithdrawal]:
        """Returns the funds needed to cover a withdrawal of the specified amount
        
        Raises:
            ValueError: if the amount specified is more than the total available funds in the wallet"""

        if self.balance < amount:
            raise ValueError('Not enough funds to cover transfer')

        total = 0
        funds: list[FundWithdrawal] = []
        for fund in self:
            withdrawal_amount = min(fund.available, amount - total)

            withdrawal = FundWithdrawal(
                receipt_id=fund.receipt.uuid,
                amount=withdrawal_amount
            )

            total += withdrawal_amount
            funds.append(withdrawal)
            if total >= amount:
                break
        return funds

    def update_credit(self, receipt: Receipt):
        '''Updates the internally tracked credit based on the receipt'''
        contract = receipt.contract

        if contract.payee_address == self.address:
            fund = TrackedFund(receipt=receipt)
            self._funds.append(fund)
            self._fund_dict[receipt] = fund
        elif contract.payer_address == self.address:
            for withdrawal in contract.funds:
                if withdrawal.receipt_id not in self._fund_dict:
                    continue
                fund = self._fund_dict[withdrawal.receipt_id]
                fund.log_withdrawal(withdrawal, receipt)
                if fund.remaining == 0:
                    self._funds.remove(fund)
                    del self._fund_dict[withdrawal.receipt_id]
        else:
            raise Exception("Please use ReceiptBook for tracking transactions that don't involve this wallet")
        
        self._funds.sort(key = lambda tf: tf.remaining)
        self._balance = sum(fund.available for fund in self._funds)

    def reserve_credit(self, details: ...):
        '''Updates the internally tracked credit based on the ...'''
        ...

    def release_credit(self, details: ...):
        '''Updates the internally tracked credit based on the ...'''
        ...
    
    def __iter__(self):
        return iter(self._funds)
    
    @property
    def balance(self) -> int:
        return self._balance