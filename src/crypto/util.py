import base64
import hashlib
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from settings import SIG_HASH, SIG_KEY_SIZE, SIG_PADDING, SIG_PUBLIC_EXPONENT
from util.type_adapters import get_type_adapter

if TYPE_CHECKING:
    from protocol.dialogue.util.rng_seed import RNGSeed


class PublicKey:
    """Wrapper for the cryptography public key class"""

    def __init__(self, key: RSAPublicKey):
        self._key = key
        self._key_str = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    @classmethod
    def from_pem(cls, pem: str):
        public_key = load_pem_public_key(pem.encode("utf-8"))
        assert isinstance(public_key, rsa.RSAPublicKey)
        return PublicKey(public_key)

    def verify(self, signature: bytes, message: bytes):
        self._key.verify(signature, message, SIG_PADDING, SIG_HASH)

    def as_str(self):
        return self._key_str

    def __str__(self):
        return self.as_str()


class PrivateKey:
    """Wrapper for the cryptography private key class"""

    def __init__(self, key: RSAPrivateKey):
        self._key = key
        self._key_str = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    @classmethod
    def from_pem(cls, pem: str):
        private_key = load_pem_private_key(pem.encode("utf-8"), password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        return PrivateKey(private_key)

    def sign(self, message: bytes):
        signature = self._key.sign(message, SIG_PADDING, SIG_HASH)
        return base64.b64encode(signature).decode("utf-8")

    def as_str(self):
        return self._key_str

    def __str__(self):
        return self.as_str()


def to_bytes(obj: Any) -> bytes:
    return get_type_adapter(Any).dump_json(obj)


def to_sha256(obj: Any):
    byts = to_bytes(obj)
    return hashlib.sha256(byts).hexdigest()


class RandomGen:
    """Transparent random generator function"""

    def __init__(self, seed: "RNGSeed"):
        self.seed_bytes = seed.seed_bytes()
        self.count = 0

    def next(self, max_value: int):
        """Random int [0,max_value)"""

        max_unbiased = (1 << 256) - ((1 << 256) % max_value)

        while True:
            hash_bytes = hashlib.sha256(
                self.seed_bytes + self.count.to_bytes(8, "big")
            ).digest()
            num = int.from_bytes(hash_bytes, "big")

            if num >= max_unbiased:
                continue

            self.count += 1
            return num % max_value


def generate_keypair():
    """Returns a public/private keypair in pem format

    Return:
        (public_key: str, private_key: str)"""

    private_key = rsa.generate_private_key(
        public_exponent=SIG_PUBLIC_EXPONENT,
        key_size=SIG_KEY_SIZE,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    return PublicKey(public_key), PrivateKey(private_key)
