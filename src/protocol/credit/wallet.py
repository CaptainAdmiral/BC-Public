from protocol.credit.tracked_fund import TrackedFund
from protocol.credit.credit_types import FundWithdrawal, Receipt
from protocol.dialogue.util.rng_seed import WitnessSelectionRNGData
from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
from settings import TIME_TO_CONSISTENCY

class Wallet:
    
    def __init__(self, address) -> None:
        self.address = address
        self._funds: list[TrackedFund] = []
        '''Sorted list of active transaction receipts into the account by amount (ascending)'''
        self._fund_dict: dict[str, TrackedFund] = {}

    @property
    def balance(self):
        return sum(fund.available for fund in self._funds)

    def find_funds(self, amount: int, event_timeline: VerificationNetTimeline) -> list[FundWithdrawal]:
        """Returns the funds needed to cover a withdrawal of the specified amount
        
        Raises:
            ValueError: if the amount specified is more than the total available funds in the wallet"""

        if self.balance < amount:
            raise ValueError('Not enough funds to cover transfer')

        total = 0
        funds: list[FundWithdrawal] = []
        for fund in self:
            withdrawal_amount = min(fund.available, amount - total)
            timestamp = fund.receipt.contract.timestamp 
            missing_events = event_timeline.events_by_time_added(timestamp - TIME_TO_CONSISTENCY, timestamp)
            missing_ids = tuple(event.event.data.id for event in missing_events) 

            withdrawal = FundWithdrawal(
                receipt_id=fund.receipt.id,
                rng_seed=WitnessSelectionRNGData(
                    timestamp=fund.receipt.contract.timestamp,
                    payee_public_key=fund.receipt.contract.payee_public_key,
                    payer_public_key=fund.receipt.contract.payer_public_key,
                ),
                witnesses=fund.receipt.contract.witnesses,
                missing_event_ids=missing_ids,
                amount=withdrawal_amount,
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
            self._fund_dict[receipt.id] = fund
        elif contract.payer_address == self.address:
            for withdrawal in contract.funds:
                if withdrawal.receipt_id not in self._fund_dict:
                    continue
                fund = self._fund_dict[withdrawal.receipt_id]
                fund.withdraw_credit(withdrawal, receipt)
                if fund.remaining == 0:
                    self._funds.remove(fund)
                    del self._fund_dict[withdrawal.receipt_id]
        else:
            raise Exception("Please use ReceiptBook for tracking transactions that don't involve this wallet")
        
        self._funds.sort(key = lambda tf: tf.remaining)
    
    def get_fund(self, receipt_id: str) -> TrackedFund:
        return self._fund_dict[receipt_id]

    def __iter__(self):
        return iter(self._funds)