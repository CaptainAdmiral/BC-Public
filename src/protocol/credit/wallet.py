import bisect

from protocol.credit.credit_types import FundTypes, FundWithdrawal, Receipt
from protocol.credit.tracked_fund import TrackedFund
from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
from settings import TIME_TO_CONSISTENCY


class Wallet:

    def __init__(self, address) -> None:
        self.address = address
        self._funds: list[TrackedFund] = []
        """Sorted list of active transaction receipts into the account by amount (ascending)"""
        self._fund_dict: dict[str, TrackedFund] = {}

    @property
    def balance(self):
        return sum(fund.available for fund in self._funds)

    def total_credit(self):
        return sum(fund.total_credit() for fund in self._funds)

    def find_funds(
        self, amount: int, event_timeline: VerificationNetTimeline
    ) -> list[FundWithdrawal]:
        """Returns the funds needed to cover a withdrawal of the specified amount

        Raises:
            ValueError: if the amount specified is more than the total available funds in the wallet
        """

        if self.balance < amount:
            raise ValueError("Not enough funds to cover transfer")

        total = 0
        funds: list[FundWithdrawal] = []
        for fund in self:
            withdrawal_amount = min(fund.available, amount - total)
            timestamp = fund.details.timestamp
            missing_events = event_timeline.events_by_time_added(
                timestamp - TIME_TO_CONSISTENCY, timestamp
            )
            missing_ids = tuple(event.event.data.id for event in missing_events)

            withdrawal = FundWithdrawal(
                fund_id=fund.id,
                fund_timestamp=fund.details.timestamp,
                rng_seed=fund.details.rng_seed,
                witnesses=fund.details.witnesses,
                missing_event_ids=missing_ids,
                amount=withdrawal_amount,
            )

            total += withdrawal_amount
            funds.append(withdrawal)
            if total >= amount:
                break
        return funds

    def add_credit(self, fund: FundTypes):
        """Updates the internally tracked credit based on the fund"""

        tracked_fund = TrackedFund(id=fund.id, details=fund)
        bisect.insort_right(self._funds, tracked_fund, key=lambda tf: tf.remaining)
        self._fund_dict[tracked_fund.id] = tracked_fund

    def deduct_credit(self, receipt: Receipt):
        """Deducts the receipt from the internally tracked credit"""

        contract = receipt.contract

        assert contract.payer_address == self.address

        for withdrawal in contract.funds:
            if withdrawal.fund_id not in self._fund_dict:
                continue
            fund = self._fund_dict[withdrawal.fund_id]
            fund.withdraw_credit(withdrawal, receipt)
            if fund.remaining == 0:
                self._funds.remove(fund)
                del self._fund_dict[withdrawal.fund_id]

        self._funds.sort(key=lambda tf: tf.remaining)

    def get_fund(self, fund_id: str) -> TrackedFund:
        return self._fund_dict[fund_id]

    def __getitem__(self, key: str) -> TrackedFund:
        return self.get_fund(key)

    def __iter__(self):
        return iter(self._funds)
