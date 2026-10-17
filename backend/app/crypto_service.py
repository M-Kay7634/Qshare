
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12
KEY_SIZE = 32  # 32 bytes = 256 bits


def generate_key() -> bytes:
    """Generate a fresh random AES-256 key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Encrypt bytes with AES-256-GCM.

    Returns:
        nonce, ciphertext_with_authentication_tag
    """
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        associated_data,
    )

    return nonce, ciphertext


def decrypt_bytes(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """
    Decrypt and authenticate AES-256-GCM ciphertext.

    Raises InvalidTag if the ciphertext, authentication tag,
    key, nonce, or associated data is incorrect.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM requires a 12-byte nonce.")

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        associated_data,
    )
