
import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem

from app.hybrid_crypto_service import (
    MAGIC,
    decrypt_hybrid,
    encrypt_hybrid,
)


def test_hybrid_encrypt_decrypt_roundtrip():
    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()
    original = b"QShare post-quantum hybrid encryption test."

    encrypted = encrypt_hybrid(original, public_key)
    decrypted = decrypt_hybrid(encrypted, private_key)

    assert encrypted != original
    assert encrypted.startswith(MAGIC)
    assert decrypted == original


def test_hybrid_modified_payload_is_rejected():
    private_key = mlkem.MLKEM768PrivateKey.generate()
    encrypted = bytearray(
        encrypt_hybrid(b"Confidential file content", private_key.public_key())
    )
    encrypted[-1] ^= 1

    with pytest.raises(InvalidTag):
        decrypt_hybrid(bytes(encrypted), private_key)


def test_hybrid_wrong_private_key_is_rejected():
    recipient_private = mlkem.MLKEM768PrivateKey.generate()
    other_private = mlkem.MLKEM768PrivateKey.generate()

    encrypted = encrypt_hybrid(
        b"Private QShare data", recipient_private.public_key()
    )

    with pytest.raises(InvalidTag):
        decrypt_hybrid(encrypted, other_private)


def test_hybrid_invalid_format_is_rejected():
    private_key = mlkem.MLKEM768PrivateKey.generate()

    with pytest.raises(ValueError):
        decrypt_hybrid(b"not a QShare file", private_key)


def test_hybrid_empty_file_roundtrip():
    private_key = mlkem.MLKEM768PrivateKey.generate()

    encrypted = encrypt_hybrid(b"", private_key.public_key())

    assert decrypt_hybrid(encrypted, private_key) == b""
