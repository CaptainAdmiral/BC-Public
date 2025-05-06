from abc import ABC
from dataclasses import dataclass
from enum import StrEnum, auto
from typing import Literal
from uuid import UUID

from cryptography.signature import Signed
from protocol.std_protocol.std_protocol import VerificationNodeData

class ContractType(StrEnum):
    TRANSACTION = auto()
    STAKE = auto()

@dataclass(frozen=True)
class Contract(ABC):
    contract_type: ContractType

@dataclass(frozen=True)
class FundWithdrawal:
    receipt_id: UUID
    amount: int

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
    vnt_cutoff: float

@dataclass(frozen=True)
class Receipt(Signed[Transaction]):
    uuid: UUID
    
    @property
    def contract(self):
        return self.message
    
    def __hash__(self):
        return hash(self.uuid)
    
@dataclass(frozen=True)
class Stake(Contract):
    contract_type: Literal[ContractType.STAKE]
    address: int
    public_key: str
    amount: int
    funds: tuple[FundWithdrawal, ...]
    timestamp: float
