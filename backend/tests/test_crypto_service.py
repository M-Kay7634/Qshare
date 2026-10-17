
import pytest

from cryptography.exceptions import InvalidTag

from app.crypto_service import (
    generate_key,
    encrypt_bytes,
    decrypt_bytes,
)


def test_encrypt_and_decrypt():
    original = b"QShare secure file sharing test"

    key = generate_key()
    nonce, ciphertext = encrypt_bytes(original, key)

    recovered = decrypt_bytes(ciphertext, key, nonce)

    assert recovered == original
    assert ciphertext != original


def test_tampered_ciphertext_is_rejected():
    original = b"Confidential QShare document"

    key = generate_key()
    nonce, ciphertext = encrypt_bytes(original, key)

    modified = bytearray(ciphertext)
    modified[0] ^= 1

    with pytest.raises(InvalidTag):
        decrypt_bytes(bytes(modified), key, nonce)


def test_wrong_key_is_rejected():
    key1 = generate_key()
    key2 = generate_key()

    nonce, ciphertext = encrypt_bytes(
        b"Test document",
        key1,
    )

    with pytest.raises(InvalidTag):
        decrypt_bytes(ciphertext, key2, nonce)


def test_associated_data_must_match():
    key = generate_key()

    nonce, ciphertext = encrypt_bytes(
        b"QShare file",
        key,
        associated_data=b"file-id-123",
    )

    with pytest.raises(InvalidTag):
        decrypt_bytes(
            ciphertext,
            key,
            nonce,
            associated_data=b"file-id-456",
        )
