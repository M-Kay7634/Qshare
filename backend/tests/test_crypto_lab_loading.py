"""Tests for loading keys separately from using them (app/crypto_lab.py).

The benchmarks time "load the key" and "use the key" as two different steps,
so both ways of calling the code must agree.
"""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto_lab import KEMS, get_kem

_keypairs = {}


def keypair(kem):
    """Generate each algorithm's key pair once (RSA keygen is slow)."""
    if kem.name not in _keypairs:
        _keypairs[kem.name] = kem.generate_keypair()
    return _keypairs[kem.name]


kem_params = pytest.mark.parametrize("kem", KEMS, ids=lambda k: k.name)


@kem_params
def test_loaded_key_api_gives_the_same_result_as_the_bytes_api(kem):
    public_key, private_key = keypair(kem)

    loaded_public = kem.load_public_key(public_key)
    loaded_private = kem.load_private_key(private_key)

    secret, kem_ciphertext = kem.encapsulate_with(loaded_public)
    assert kem.decapsulate_with(loaded_private, kem_ciphertext) == secret
    assert kem.decapsulate(private_key, kem_ciphertext) == secret

    second_secret, second_ciphertext = kem.encapsulate(public_key)
    assert kem.decapsulate_with(loaded_private, second_ciphertext) == second_secret


@kem_params
def test_loading_garbage_keys_is_rejected(kem):
    with pytest.raises(ValueError):
        kem.load_public_key(b"garbage")
    with pytest.raises(ValueError):
        kem.load_private_key(b"garbage")


def test_rsa_loaders_reject_valid_keys_of_another_type():
    rsa_kem = get_kem("RSA-2048")
    other = ec.generate_private_key(ec.SECP256R1())
    private_der = other.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_der = other.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with pytest.raises(ValueError):
        rsa_kem.load_private_key(private_der)
    with pytest.raises(ValueError):
        rsa_kem.load_public_key(public_der)