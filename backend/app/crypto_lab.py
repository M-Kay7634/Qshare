"""QShare crypto lab: interchangeable key-establishment and AEAD algorithms.

PURPOSE
  Research code for the QShare project. It runs the SAME file-encryption
  flow with different algorithms, so they can be compared fairly:
      key establishment : ML-KEM-768, ML-KEM-1024, X25519, ECDH P-256,
                          RSA-2048, RSA-3072, hybrid X25519 + ML-KEM-768
      file encryption   : AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305

  The live QShare app does NOT use this module yet. It still uses
  hybrid_crypto_service.py and its QSHARE01 file format.

HOW A FILE IS ENCRYPTED
  1. The key-establishment step ("KEM") creates a fresh shared secret for
     this one file, plus a "KEM ciphertext" that only the owner of the
     private key can open.
  2. HKDF-SHA256 turns the shared secret into a one-time file key. It uses
     a random salt, and the whole file header is mixed in as context.
  3. The AEAD cipher encrypts and authenticates the file. The header is
     authenticated too, so changing any byte of it makes decryption fail.

  Every file gets its own fresh key, so the random 96-bit nonce can never
  be reused under the same key.

FILE FORMAT "QSHARE02"
  magic(8) | kem_id(1) | aead_id(1) | kem_ct_len(2, big-endian)
  | kem_ct | salt(16) | nonce(12) | ciphertext + tag(16)

LAB ONLY: private keys are exported as plain bytes so benchmarks can
measure them. Never store private keys like this in the real app.

NOTE ON THE HYBRID: "X25519+ML-KEM-768" joins the two shared secrets and
the two KEM ciphertexts, then feeds them to HKDF. It is in the spirit of
hybrid designs used in practice, but it is NOT a byte-exact copy of the
TLS "X25519MLKEM768" construction.
"""

import os
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    mlkem,
    padding,
    rsa,
    x25519,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"QSHARE02"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
FIXED_HEADER_SIZE = len(MAGIC) + 1 + 1 + 2  # magic + kem_id + aead_id + length
KDF_LABEL = b"QShare crypto lab v2"


# ---------------------------------------------------------------------------
# Key establishment ("KEM") algorithms
# ---------------------------------------------------------------------------
class KeyEstablishment(ABC):
    """One way of agreeing a fresh shared secret with a key holder."""

    def __init__(self, kem_id: int, name: str, ciphertext_size: int):
        self.kem_id = kem_id
        self.name = name
        self.ciphertext_size = ciphertext_size

    @abstractmethod
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key_bytes, private_key_bytes)."""

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (shared_secret, kem_ciphertext) for this public key."""

    @abstractmethod
    def decapsulate(self, private_key: bytes, kem_ciphertext: bytes) -> bytes:
        """Return the shared secret."""


class MlKem(KeyEstablishment):
    """ML-KEM (FIPS 203). The private key is stored as its 64-byte seed."""

    def __init__(self, kem_id, name, ciphertext_size, private_cls, public_cls):
        super().__init__(kem_id, name, ciphertext_size)
        self._private_cls = private_cls
        self._public_cls = public_cls

    def generate_keypair(self):
        private_key = self._private_cls.generate()
        return (
            private_key.public_key().public_bytes_raw(),
            private_key.private_bytes_raw(),
        )

    def encapsulate(self, public_key):
        public = self._public_cls.from_public_bytes(public_key)
        shared_secret, kem_ciphertext = public.encapsulate()
        return shared_secret, kem_ciphertext

    def decapsulate(self, private_key, kem_ciphertext):
        private = self._private_cls.from_seed_bytes(private_key)
        return private.decapsulate(kem_ciphertext)


class X25519Kem(KeyEstablishment):
    """Elliptic-curve Diffie-Hellman on Curve25519 (ephemeral-static)."""

    def __init__(self, kem_id=3):
        super().__init__(kem_id, "X25519", 32)

    def generate_keypair(self):
        private_key = x25519.X25519PrivateKey.generate()
        return (
            private_key.public_key().public_bytes_raw(),
            private_key.private_bytes_raw(),
        )

    def encapsulate(self, public_key):
        peer = x25519.X25519PublicKey.from_public_bytes(public_key)
        ephemeral = x25519.X25519PrivateKey.generate()
        shared_secret = ephemeral.exchange(peer)
        return shared_secret, ephemeral.public_key().public_bytes_raw()

    def decapsulate(self, private_key, kem_ciphertext):
        private = x25519.X25519PrivateKey.from_private_bytes(private_key)
        peer = x25519.X25519PublicKey.from_public_bytes(kem_ciphertext)
        return private.exchange(peer)


class EcdhP256Kem(KeyEstablishment):
    """Elliptic-curve Diffie-Hellman on NIST P-256 (ephemeral-static)."""

    def __init__(self, kem_id=4):
        super().__init__(kem_id, "ECDH-P256", 65)
        self._curve = ec.SECP256R1()

    def _point(self, public_key) -> bytes:
        return public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def generate_keypair(self):
        private_key = ec.generate_private_key(self._curve)
        private_value = private_key.private_numbers().private_value
        return self._point(private_key.public_key()), private_value.to_bytes(32, "big")

    def encapsulate(self, public_key):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(self._curve, public_key)
        ephemeral = ec.generate_private_key(self._curve)
        shared_secret = ephemeral.exchange(ec.ECDH(), peer)
        return shared_secret, self._point(ephemeral.public_key())

    def decapsulate(self, private_key, kem_ciphertext):
        private = ec.derive_private_key(int.from_bytes(private_key, "big"), self._curve)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(self._curve, kem_ciphertext)
        return private.exchange(ec.ECDH(), peer)


class RsaOaepKem(KeyEstablishment):
    """RSA key transport: a random secret encrypted with RSA-OAEP-SHA256."""

    def __init__(self, kem_id, bits):
        super().__init__(kem_id, f"RSA-{bits}", bits // 8)
        self._bits = bits
        self._padding = padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

    def generate_keypair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self._bits
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return public_bytes, private_bytes

    def encapsulate(self, public_key):
        public = serialization.load_der_public_key(public_key)
        if not isinstance(public, rsa.RSAPublicKey):
            raise ValueError("Not an RSA public key.")
        shared_secret = os.urandom(32)
        return shared_secret, public.encrypt(shared_secret, self._padding)

    def decapsulate(self, private_key, kem_ciphertext):
        private = serialization.load_der_private_key(private_key, password=None)
        if not isinstance(private, rsa.RSAPrivateKey):
            raise ValueError("Not an RSA private key.")
        return private.decrypt(kem_ciphertext, self._padding)


class HybridX25519MlKem768(KeyEstablishment):
    """Classical + post-quantum: both secrets are combined, so an attacker
    must break BOTH X25519 and ML-KEM-768 to recover the file key."""

    _CLASSICAL_PUBLIC = 32
    _CLASSICAL_PRIVATE = 32
    _CLASSICAL_CT = 32

    def __init__(self, classical, post_quantum, kem_id=7):
        super().__init__(
            kem_id,
            "X25519+ML-KEM-768",
            classical.ciphertext_size + post_quantum.ciphertext_size,
        )
        self._classical = classical
        self._post_quantum = post_quantum

    def generate_keypair(self):
        classical_public, classical_private = self._classical.generate_keypair()
        pq_public, pq_private = self._post_quantum.generate_keypair()
        return classical_public + pq_public, classical_private + pq_private

    def encapsulate(self, public_key):
        split = self._CLASSICAL_PUBLIC
        classical_secret, classical_ct = self._classical.encapsulate(public_key[:split])
        pq_secret, pq_ct = self._post_quantum.encapsulate(public_key[split:])
        return classical_secret + pq_secret, classical_ct + pq_ct

    def decapsulate(self, private_key, kem_ciphertext):
        key_split = self._CLASSICAL_PRIVATE
        ct_split = self._CLASSICAL_CT
        classical_secret = self._classical.decapsulate(
            private_key[:key_split], kem_ciphertext[:ct_split]
        )
        pq_secret = self._post_quantum.decapsulate(
            private_key[key_split:], kem_ciphertext[ct_split:]
        )
        return classical_secret + pq_secret


# ---------------------------------------------------------------------------
# File-encryption (AEAD) algorithms
# ---------------------------------------------------------------------------
class Aead:
    """Authenticated encryption: hides the data AND detects any change."""

    def __init__(self, aead_id: int, name: str, key_size: int, cipher_cls):
        self.aead_id = aead_id
        self.name = name
        self.key_size = key_size
        self._cipher_cls = cipher_cls

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._cipher_cls(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        return self._cipher_cls(key).decrypt(nonce, data, aad)


# ---------------------------------------------------------------------------
# Registry (the numeric ids are written into the file header: never reuse one)
# ---------------------------------------------------------------------------
ML_KEM_768 = MlKem(
    1, "ML-KEM-768", 1088, mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey
)
ML_KEM_1024 = MlKem(
    2, "ML-KEM-1024", 1568, mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey
)
X25519_KEM = X25519Kem(3)

KEMS = [
    ML_KEM_768,
    ML_KEM_1024,
    X25519_KEM,
    EcdhP256Kem(4),
    RsaOaepKem(5, 2048),
    RsaOaepKem(6, 3072),
    HybridX25519MlKem768(X25519_KEM, ML_KEM_768, 7),
]

AEADS = [
    Aead(1, "AES-128-GCM", 16, AESGCM),
    Aead(2, "AES-256-GCM", 32, AESGCM),
    Aead(3, "ChaCha20-Poly1305", 32, ChaCha20Poly1305),
]

_KEMS_BY_ID = {kem.kem_id: kem for kem in KEMS}
_AEADS_BY_ID = {aead.aead_id: aead for aead in AEADS}


def get_kem(name: str) -> KeyEstablishment:
    for kem in KEMS:
        if kem.name == name:
            return kem
    raise ValueError(f"Unknown key-establishment algorithm: {name}")


def get_aead(name: str) -> Aead:
    for aead in AEADS:
        if aead.name == name:
            return aead
    raise ValueError(f"Unknown file-encryption algorithm: {name}")


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------
def _derive_file_key(shared_secret: bytes, salt: bytes, header: bytes, size: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=size,
        salt=salt,
        info=KDF_LABEL + header,
    ).derive(shared_secret)


def encrypt(
    plaintext: bytes,
    recipient_public_key: bytes,
    kem: KeyEstablishment,
    aead: Aead,
) -> bytes:
    """Encrypt bytes for the owner of recipient_public_key."""
    shared_secret, kem_ciphertext = kem.encapsulate(recipient_public_key)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = (
        MAGIC
        + bytes([kem.kem_id, aead.aead_id])
        + len(kem_ciphertext).to_bytes(2, "big")
        + kem_ciphertext
        + salt
        + nonce
    )
    file_key = _derive_file_key(shared_secret, salt, header, aead.key_size)
    return header + aead.encrypt(file_key, nonce, plaintext, header)


def decrypt(payload: bytes, recipient_private_key: bytes) -> bytes:
    """Decrypt a QSHARE02 payload. The algorithms are read from its header.

    Raises ValueError for a malformed or unknown format, and InvalidTag if
    the key is wrong or the data was modified.
    """
    if len(payload) < FIXED_HEADER_SIZE:
        raise ValueError("Encrypted payload is incomplete.")
    if payload[: len(MAGIC)] != MAGIC:
        raise ValueError("Unrecognized QShare encrypted-file format.")

    kem = _KEMS_BY_ID.get(payload[8])
    aead = _AEADS_BY_ID.get(payload[9])
    if kem is None or aead is None:
        raise ValueError("Unknown algorithm in the file header.")

    kem_ct_len = int.from_bytes(payload[10:12], "big")
    if kem_ct_len != kem.ciphertext_size:
        raise ValueError("Malformed file header.")

    header_size = FIXED_HEADER_SIZE + kem_ct_len + SALT_SIZE + NONCE_SIZE
    if len(payload) < header_size + TAG_SIZE:
        raise ValueError("Encrypted payload is incomplete.")

    offset = FIXED_HEADER_SIZE
    kem_ciphertext = payload[offset : offset + kem_ct_len]
    offset += kem_ct_len
    salt = payload[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = payload[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    header = payload[:offset]
    body = payload[offset:]

    shared_secret = kem.decapsulate(recipient_private_key, kem_ciphertext)
    file_key = _derive_file_key(shared_secret, salt, header, aead.key_size)

    try:
        return aead.decrypt(file_key, nonce, body, header)
    except InvalidTag:
        raise InvalidTag("Decryption failed: wrong key or modified payload.")