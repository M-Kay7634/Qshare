"""Tests for app/crypto_lab.py (the research crypto core)."""

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem

from app import crypto_lab
from app.crypto_lab import (
    AEADS,
    FIXED_HEADER_SIZE,
    KEMS,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    decrypt,
    encrypt,
    get_aead,
    get_kem,
)
from app.hybrid_crypto_service import decrypt_hybrid, encrypt_hybrid

AES_256 = get_aead("AES-256-GCM")
BAD_INPUT = (ValueError, InvalidTag)

_keypairs = {}
_other_keypairs = {}


def keypair(kem):
    """Generate each algorithm's key pair once (RSA keygen is slow)."""
    if kem.name not in _keypairs:
        _keypairs[kem.name] = kem.generate_keypair()
    return _keypairs[kem.name]


def other_keypair(kem):
    if kem.name not in _other_keypairs:
        _other_keypairs[kem.name] = kem.generate_keypair()
    return _other_keypairs[kem.name]


kem_params = pytest.mark.parametrize("kem", KEMS, ids=lambda k: k.name)
aead_params = pytest.mark.parametrize("aead", AEADS, ids=lambda a: a.name)


# --- registry ---------------------------------------------------------------
def test_algorithm_ids_and_names_are_unique():
    assert len({k.kem_id for k in KEMS}) == len(KEMS)
    assert len({k.name for k in KEMS}) == len(KEMS)
    assert len({a.aead_id for a in AEADS}) == len(AEADS)
    assert len({a.name for a in AEADS}) == len(AEADS)


def test_lookup_by_name_and_unknown_name():
    assert get_kem("ML-KEM-768").kem_id == 1
    assert get_aead("ChaCha20-Poly1305").aead_id == 3
    with pytest.raises(ValueError):
        get_kem("not-a-real-algorithm")
    with pytest.raises(ValueError):
        get_aead("not-a-real-cipher")


# --- correctness: every key-establishment x every cipher --------------------
@kem_params
@aead_params
@pytest.mark.parametrize("size", [0, 1, 1000, 100_000])
def test_round_trip(kem, aead, size):
    public_key, private_key = keypair(kem)
    plaintext = bytes(i % 251 for i in range(size))

    payload = encrypt(plaintext, public_key, kem, aead)

    assert decrypt(payload, private_key) == plaintext


@kem_params
def test_wrong_private_key_cannot_decrypt(kem):
    public_key, _ = keypair(kem)
    _, wrong_private_key = other_keypair(kem)
    payload = encrypt(b"secret data", public_key, kem, AES_256)

    with pytest.raises(BAD_INPUT):
        decrypt(payload, wrong_private_key)


@kem_params
def test_same_plaintext_gives_different_ciphertext_each_time(kem):
    public_key, _ = keypair(kem)
    first = encrypt(b"same message", public_key, kem, AES_256)
    second = encrypt(b"same message", public_key, kem, AES_256)

    assert first != second
    salt_nonce = slice(-(TAG_SIZE + len(b"same message") + NONCE_SIZE),
                       -(TAG_SIZE + len(b"same message")))
    assert first[salt_nonce] != second[salt_nonce]  # nonce is never reused


# --- sizes (facts we will report in the research paper) ---------------------
@kem_params
@aead_params
def test_overhead_is_exactly_the_header_plus_tag(kem, aead):
    public_key, _ = keypair(kem)
    plaintext = b"x" * 777
    payload = encrypt(plaintext, public_key, kem, aead)

    expected_overhead = (
        FIXED_HEADER_SIZE + kem.ciphertext_size + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    )
    assert len(payload) - len(plaintext) == expected_overhead


def test_published_ml_kem_sizes():
    # FIPS 203: ML-KEM-768 public key 1184 / ciphertext 1088,
    #           ML-KEM-1024 public key 1568 / ciphertext 1568.
    public, private = keypair(get_kem("ML-KEM-768"))
    assert (len(public), len(private)) == (1184, 64)
    public, private = keypair(get_kem("ML-KEM-1024"))
    assert (len(public), len(private)) == (1568, 64)


@kem_params
def test_declared_ciphertext_size_matches_reality(kem):
    public_key, _ = keypair(kem)
    _, kem_ciphertext = kem.encapsulate(public_key)
    assert len(kem_ciphertext) == kem.ciphertext_size


def test_ml_kem_768_is_compatible_with_the_live_app_primitives():
    """Lab ML-KEM-768 keys also work with the live QSHARE01 code."""
    kem = get_kem("ML-KEM-768")
    public_bytes, private_bytes = keypair(kem)
    public_key = mlkem.MLKEM768PublicKey.from_public_bytes(public_bytes)
    private_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(private_bytes)

    payload = encrypt_hybrid(b"interop check", public_key)

    assert decrypt_hybrid(payload, private_key) == b"interop check"


# --- tampering: changing ANY part must be detected --------------------------
@kem_params
def test_changing_any_part_of_the_file_is_detected(kem):
    public_key, private_key = keypair(kem)
    payload = encrypt(b"do not touch" * 10, public_key, kem, AES_256)

    ct_start = FIXED_HEADER_SIZE
    salt_start = ct_start + kem.ciphertext_size
    nonce_start = salt_start + SALT_SIZE
    body_start = nonce_start + NONCE_SIZE
    positions = {
        "magic": 0,
        "kem id": 8,
        "aead id": 9,
        "length field": 11,
        "first kem ciphertext byte": ct_start,
        "last kem ciphertext byte": salt_start - 1,
        "salt": salt_start,
        "nonce": nonce_start,
        "first encrypted byte": body_start,
        "last tag byte": len(payload) - 1,
    }

    for label, position in positions.items():
        damaged = bytearray(payload)
        damaged[position] ^= 0x01
        with pytest.raises(BAD_INPUT):
            decrypt(bytes(damaged), private_key)
    # sanity: the untouched file still decrypts
    assert decrypt(payload, private_key) == b"do not touch" * 10


# --- malformed input is rejected safely -------------------------------------
@kem_params
def test_every_too_short_payload_is_rejected(kem):
    public_key, private_key = keypair(kem)
    payload = encrypt(b"abc", public_key, kem, AES_256)
    minimum = FIXED_HEADER_SIZE + kem.ciphertext_size + SALT_SIZE + NONCE_SIZE + TAG_SIZE

    for length in range(minimum):
        with pytest.raises(ValueError):
            decrypt(payload[:length], private_key)

    # cutting only the last byte keeps the shape but breaks authentication
    with pytest.raises(InvalidTag):
        decrypt(payload[:-1], private_key)


def test_unknown_format_and_unknown_algorithm_ids_are_rejected():
    kem = get_kem("X25519")
    public_key, private_key = keypair(kem)
    payload = bytearray(encrypt(b"hello", public_key, kem, AES_256))

    wrong_magic = bytearray(payload)
    wrong_magic[:8] = b"QSHARE01"
    with pytest.raises(ValueError):
        decrypt(bytes(wrong_magic), private_key)

    unknown_kem = bytearray(payload)
    unknown_kem[8] = 99
    with pytest.raises(ValueError):
        decrypt(bytes(unknown_kem), private_key)

    unknown_aead = bytearray(payload)
    unknown_aead[9] = 99
    with pytest.raises(ValueError):
        decrypt(bytes(unknown_aead), private_key)

    with pytest.raises(ValueError):
        decrypt(b"", private_key)
    with pytest.raises(ValueError):
        decrypt(b"QSHARE02", private_key)


def test_header_length_field_that_lies_is_rejected():
    kem = get_kem("ML-KEM-768")
    public_key, private_key = keypair(kem)
    payload = bytearray(encrypt(b"hello", public_key, kem, AES_256))
    payload[10:12] = (60000).to_bytes(2, "big")

    with pytest.raises(ValueError):
        decrypt(bytes(payload), private_key)


def test_a_key_of_the_wrong_kind_is_rejected():
    rsa_kem = get_kem("RSA-2048")
    x_public, x_private = keypair(get_kem("X25519"))
    payload = encrypt(b"hello", x_public, get_kem("X25519"), AES_256)

    # An RSA private key cannot open an X25519 file.
    _, rsa_private = keypair(rsa_kem)
    with pytest.raises(BAD_INPUT):
        decrypt(payload, rsa_private)


def test_hybrid_needs_both_halves_of_the_key():
    """An attacker with only ONE of the two private keys must fail."""
    hybrid = get_kem("X25519+ML-KEM-768")
    public_key, private_key = keypair(hybrid)
    _, other_private = other_keypair(hybrid)
    payload = encrypt(b"needs both", public_key, hybrid, AES_256)

    split = 32  # X25519 private key is 32 bytes, ML-KEM seed follows
    right_classical_wrong_pq = private_key[:split] + other_private[split:]
    wrong_classical_right_pq = other_private[:split] + private_key[split:]

    with pytest.raises(BAD_INPUT):
        decrypt(payload, right_classical_wrong_pq)
    with pytest.raises(BAD_INPUT):
        decrypt(payload, wrong_classical_right_pq)
    assert decrypt(payload, private_key) == b"needs both"


def test_header_is_authenticated_and_bound_to_the_file_key():
    """The header is both authenticated data and an input to the key."""
    kem = get_kem("ML-KEM-768")
    public_key, private_key = keypair(kem)
    payload = encrypt(b"bind the header", public_key, kem, AES_256)

    header_size = FIXED_HEADER_SIZE + kem.ciphertext_size + SALT_SIZE + NONCE_SIZE
    header, body = payload[:header_size], payload[header_size:]
    nonce = header[-NONCE_SIZE:]
    salt = header[-(SALT_SIZE + NONCE_SIZE) : -NONCE_SIZE]
    kem_ciphertext = header[FIXED_HEADER_SIZE : FIXED_HEADER_SIZE + kem.ciphertext_size]

    shared_secret = kem.decapsulate(private_key, kem_ciphertext)
    file_key = crypto_lab._derive_file_key(shared_secret, salt, header, AES_256.key_size)

    # With the real header as authenticated data, decryption works ...
    assert AES_256.decrypt(file_key, nonce, body, header) == b"bind the header"
    # ... and without it, authentication fails.
    with pytest.raises(InvalidTag):
        AES_256.decrypt(file_key, nonce, body, b"")

    # A different header must also produce a different file key.
    other_header = bytearray(header)
    other_header[0] ^= 0x01
    other_key = crypto_lab._derive_file_key(
        shared_secret, salt, bytes(other_header), AES_256.key_size
    )
    assert other_key != file_key