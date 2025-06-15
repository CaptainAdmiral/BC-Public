from protocol.credit.credit_types import (
    Fund,
    FundTypeEnum,
    FundTypes,
    FundWithdrawal,
    Receipt,
    GasFund,
)
from protocol.credit.tracked_fund import TrackedFund
from protocol.credit.wallet import Wallet


class ReceiptBook:

    def __init__(self, owner_pk: str) -> None:
        self.owner_pk = owner_pk
        self._tracked_funds: dict[str, TrackedFund] = {}
    
    def _add_gas(self, fund: TrackedFund, wallet: Wallet):
        for witness in fund.details.witnesses:
            withdrawals = tuple(receipt for receipt in fund.withdrawals if receipt.signed_by(witness.public_key))
            if withdrawals:
                gas_fund = GasFund(
                    FundTypeEnum.GAS,
                    fund.details.rng_seed,
                    fund.details.witnesses,
                    fund.details.timestamp,
                    fund.details,
                    withdrawals,
                    self.owner_pk,
                )
                self.add(gas_fund)
                        
        gas_fund = GasFund(
            FundTypeEnum.GAS,
            fund.details.rng_seed,
            fund.details.witnesses,
            fund.details.timestamp,
            fund.details,
            tuple(fund.withdrawals),
            self.owner_pk,
        )
        wallet.add_credit(gas_fund)

    def drop_fund(self, fund_id: str, wallet: Wallet):
        fund = self._tracked_funds[fund_id]

        if fund.details.fund_type != FundTypeEnum.GAS:
            self._add_gas(fund, wallet)

        self._remove(fund_id)

    def update_credit(
        self, withdrawal: FundWithdrawal, fund_details: Receipt, wallet: Wallet
    ):
        """Updates the internally tracked credit based on the receipt"""

        assert withdrawal in fund_details.contract.funds

        tracked_fund = self._tracked_funds[withdrawal.fund_id]
        tracked_fund.withdraw_credit(withdrawal, fund_details)
        if tracked_fund.remaining <= 0:
            self.drop_fund(tracked_fund.id, wallet)

    def add(self, fund_details: FundTypes):
        """Adds a new tracked fund to the receipt book"""

        assert fund_details not in self._tracked_funds
        tracked_fund = TrackedFund(fund_details.id, fund_details)
        if tracked_fund.remaining > 0:
            self._tracked_funds[fund_details.id] = tracked_fund

    def _remove(self, fund_id: str):
        del self._tracked_funds[fund_id]

    def get(self, key: FundTypes | str):
        if isinstance(key, Fund):
            return self._tracked_funds[key.id]
        return self._tracked_funds[key]

    def __getitem__(self, key: FundTypes | str) -> TrackedFund:
        return self.get(key)

    def __contains__(self, item: FundTypes | str):
        if isinstance(item, Fund):
            return item.id in self._tracked_funds
        return item in self._tracked_funds
