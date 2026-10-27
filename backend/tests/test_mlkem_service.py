
from cryptography.hazmat.primitives.asymmetric import mlkem

from app.mlkem_service import (
    generate_keypair,
    encapsulate_secret,
    decapsulate_secret,
)


def test_mlkem_shared_secret_matches():
    public_key, private_key = generate_keypair()

    shared_secret_sender, ciphertext = encapsulate_secret(public_key)
    shared_secret_receiver = decapsulate_secret(
        private_key, ciphertext
    )

    assert shared_secret_sender == shared_secret_receiver
    assert len(shared_secret_sender) == 32


def test_mlkem_public_key_size():
    public_key, _ = generate_keypair()
    assert len(public_key.public_bytes_raw()) == 1184


def test_mlkem_ciphertext_size():
    public_key, _ = generate_keypair()
    _, ciphertext = encapsulate_secret(public_key)
    assert len(ciphertext) == 1088
