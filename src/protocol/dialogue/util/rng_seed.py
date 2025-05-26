
from dataclasses import dataclass
import json
from typing import TYPE_CHECKING

from settings import RNG_MOD_PK

if TYPE_CHECKING:
    from protocol.verification_net.verification_net_timeline import VerificationNetTimeline

@dataclass(frozen=True)
class WitnessSelectionRNGData:
    '''Contains all the necessary information to recreate an RNGSeed used for witness selection'''

    timestamp: float
    payee_public_key: str
    payer_public_key: str

class RNGSeed:
    """Part of the seed for witness selection RNG. The actual entropy comes from the latest hash of the network
    but to prevent the same nodes from being overloaded by every transaction on that hash we determine the seed
    based on a few extra values as well."""

    def __init__(self, *, checksum: str, payee_public_key: str, payer_public_key :str):
        self.checksum = checksum
        self.payee_public_key = payee_public_key
        self.payer_public_key = payer_public_key
        self.mod_payer_pk = hash(payer_public_key) % RNG_MOD_PK
        self.mod_payee_pk = hash(payee_public_key) % RNG_MOD_PK
            
    @classmethod
    def from_dataclass(cls, seed: WitnessSelectionRNGData, vnt: 'VerificationNetTimeline'):
        checksum = vnt.get_latest_checksum(seed.timestamp)
        return RNGSeed(checksum=checksum, payee_public_key=seed.payee_public_key, payer_public_key=seed.payer_public_key)

    def seed_bytes(self) -> bytes:
        # We use mod pk here instead of pk to reduce RNG manipulation while still
        # selecting different witnesses for transactions between the same nodes on
        # the same checksum.
        return json.dumps((self.checksum, self.mod_payee_pk, self.mod_payer_pk), separators=(",", ":")).encode("utf-8")