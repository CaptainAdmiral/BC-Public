from dataclasses import dataclass

@dataclass
class WitnessSignature:

    public_address: int
    public_key: str
    signature: str

@dataclass
class Receipt:

    payer_address: int
    payer_public_key: str
    payee_address: int
    payee_public_key: str
    amount: int
    timestamp: float
    vnt_cutoff: float
    witnesses: list[WitnessSignature]