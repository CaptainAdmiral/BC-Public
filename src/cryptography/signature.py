from dataclasses import dataclass
from functools import cache
from typing import Hashable

@dataclass(frozen=True)
class Signature:

    address: int
    public_key: str
    signature: str

    def validate(self, digest: int):
        raise NotImplementedError() # TODO

@dataclass(frozen=True)
class Signed[T]:

    message: T
    signatures: frozenset[Signature]
    
    @property
    @cache
    def signatories(self):
        return set(sig.public_key for sig in self.signatures)

    def validate_signatures(self):
        digest = hash(self.message)
        for sig in self.signatures:
            sig.validate(digest)

    def with_signatures(self, *signatures: Signature):
        sigs = list(self.signatures)
        sigs.extend(signatures)
        new_sigs = frozenset(sigs)
        return Signed(message=self.message, signatures=new_sigs)
    
    def signed_by(self, public_key: str) -> bool:
        return public_key in self.signatories

class SignatureFactory:
    
    def __init__(self, public_key: str, private_key: str, address: int):
        self.public_key = public_key
        self.private_key = private_key
        self.address = address

    def get_signature(self, message: Hashable):
        return Signature(address=self.address, public_key=self.public_key, signature='PLACEHOLDER') # TODO

    def sign[T: Hashable](self, message: T, append_signature=True) -> Signed[T]:
        """Creates a Signed object containing the preimage message and a digital signature
        
        Args:
            bool: append_signatures
                If set to true and the message is already a Signed object the signature will be added to the set of signatures on the Signed object instead"""
        
        if isinstance(message, Signed) and append_signature:
            signatures = set(message.signatures)
            signatures.add(self.get_signature(message.message))
        else:
            signatures = set()
            signatures.add(self.get_signature(message))

        return Signed(message=message, signatures=frozenset(signatures))

def sign[T: Hashable](message: T, public_key: str, private_key: str, address: int) -> Signed[T]:
    sf = SignatureFactory(public_key=public_key, private_key=private_key, address=address)
    return sf.sign(message)