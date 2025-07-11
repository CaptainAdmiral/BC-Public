import base64
from abc import ABC
from dataclasses import dataclass
from functools import cache
from typing import Any, Hashable, Iterable

from cryptography.exceptions import InvalidSignature

from crypto.util import PrivateKey, PublicKey, to_bytes
from protocol.dialogue.dialogue_types import DialogueException
from settings import NODE_0_PUBLIC_KEY, VALIDATE_SIGNATURES


@dataclass(frozen=True)
class Signature:

    address: int
    public_key: str
    signature: str

    def validate(self, message: Any):
        if not VALIDATE_SIGNATURES:
            return

        if isinstance(message, ManagedSignable):
            message = message.signature_content()

        message_bytes = to_bytes(message)

        public_key = PublicKey.from_pem(self.public_key)
        signature = base64.b64decode(self.signature)
        try:
            public_key.verify(signature, message_bytes)
        except InvalidSignature:
            raise DialogueException("Invalid signature")


@dataclass(frozen=True)
class Signed[T]:

    message: T
    signatures: tuple[Signature, ...]

    @property
    @cache
    def signatories(self):
        return set(sig.public_key for sig in self.signatures)

    def validate_signatures(self):
        assert len(self.signatures) < 120
        for sig in self.signatures:
            sig.validate(self.message)

    def with_signatures(self, *signatures: Signature):
        sigs = list(self.signatures)
        sigs.extend(signatures)
        new_sigs = tuple(sigs)
        return Signed(message=self.message, signatures=new_sigs)

    def signed_by(self, public_key: str) -> bool:
        return public_key in self.signatories

    def signed_by_N0(self):
        return self.signed_by(NODE_0_PUBLIC_KEY)

    def same_as(self, other: Any) -> bool:
        if isinstance(other, Signed):
            return self.message == other.message
        return self.message == other


class ManagedSignable(ABC):

    def signature_content(self) -> Any: ...


class SignatureFactory:

    def __init__(self, public_key: PublicKey, private_key: PrivateKey, address: int):
        self.public_key = public_key
        self.private_key = private_key
        self.address = address

    def get_signature(self, message: Any):
        if isinstance(message, ManagedSignable):
            message = message.signature_content()
        message = to_bytes(message)
        signature = self.private_key.sign(message)
        return Signature(
            address=self.address,
            public_key=self.public_key.as_str(),
            signature=signature,
        )

    def sign[T: Hashable](self, message: T, append_signature=True) -> Signed[T]:
        """Creates a Signed object containing the preimage message and a digital signature

        Args:
            bool: append_signatures
                If set to true and the message is already a Signed object the signature will be added to the set of signatures on the Signed object instead
        """

        if isinstance(message, Signed) and append_signature:
            signatures = set(message.signatures)
            signatures.add(self.get_signature(message.message))
        else:
            signatures = set()
            signatures.add(self.get_signature(message))

        return Signed(message=message, signatures=tuple(signatures))


def sign[T: Hashable](
    message: T, public_key: PublicKey, private_key: PrivateKey, address: int
) -> Signed[T]:
    sf = SignatureFactory(
        public_key=public_key, private_key=private_key, address=address
    )
    return sf.sign(message)


def with_signatures(message: Any, signatures: Iterable[Signature]):
    return Signed(message=message, signatures=tuple(signatures))


@dataclass(frozen=True)
class TimestampedSignature:
    signature: Signature
    timestamp: float
