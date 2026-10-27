"""Tests for persistent, protected key storage (app/key_store.py)."""

import base64
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from app import key_store
from app.hybrid_crypto_service import decrypt_hybrid, encrypt_hybrid
from cryptography.hazmat.primitives.asymmetric import mlkem

BACKEND_DIR = Path(__file__).resolve().parent.parent
USER_A = "user-a-0001"
USER_B = "user-b-0002"


def read_row(user_id):
    connection = sqlite3.connect(key_store.DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(
            "SELECT * FROM user_keys WHERE user_id = ?", (user_id,)
        ).fetchone()
    finally:
        connection.close()


def test_unknown_user_has_no_keys():
    assert key_store.get_public_key("nobody") is None
    assert key_store.get_private_key("nobody") is None


def test_create_then_read_back_same_key_pair():
    public_bytes = key_store.create_recipient_keypair(USER_A)

    assert key_store.get_public_key(USER_A) == public_bytes
    private_key = key_store.get_private_key(USER_A)
    assert private_key.public_key().public_bytes_raw() == public_bytes


def test_private_key_is_never_stored_in_plaintext():
    key_store.create_recipient_keypair(USER_A)
    seed = key_store.get_private_key(USER_A).private_bytes_raw()

    row = read_row(USER_A)
    for column in row.keys():
        value = row[column]
        if isinstance(value, bytes):
            assert seed not in value
    # Also check the raw database file on disk.
    assert seed not in Path(key_store.DATABASE_PATH).read_bytes()


def test_key_survives_a_real_restart_in_a_new_process(tmp_path):
    """Encrypt in THIS process, decrypt in a brand-new Python process."""
    public_bytes = key_store.create_recipient_keypair(USER_A)
    public_key = mlkem.MLKEM768PublicKey.from_public_bytes(public_bytes)

    original = b"This must survive a backend restart."
    encrypted_path = tmp_path / "file.qsf"
    encrypted_path.write_bytes(encrypt_hybrid(original, public_key))

    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from app.key_store import get_private_key\n"
        "from app.hybrid_crypto_service import decrypt_hybrid\n"
        "data = Path(sys.argv[1]).read_bytes()\n"
        "key = get_private_key(sys.argv[2])\n"
        "sys.stdout.write(decrypt_hybrid(data, key).decode())\n"
    )
    environment = dict(os.environ)
    environment["QSHARE_KEYS_DB"] = str(key_store.DATABASE_PATH)

    result = subprocess.run(
        [sys.executable, "-c", script, str(encrypted_path), USER_A],
        cwd=BACKEND_DIR,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == original.decode()


def test_second_key_pair_is_refused_and_first_key_is_kept():
    first_public = key_store.create_recipient_keypair(USER_A)

    with pytest.raises(key_store.KeyAlreadyExistsError):
        key_store.create_recipient_keypair(USER_A)

    assert key_store.get_public_key(USER_A) == first_public


def test_users_have_separate_keys():
    public_a = key_store.create_recipient_keypair(USER_A)
    public_b = key_store.create_recipient_keypair(USER_B)

    assert public_a != public_b
    assert key_store.get_public_key(USER_A) == public_a
    assert key_store.get_public_key(USER_B) == public_b


def test_wrong_master_key_cannot_unlock(monkeypatch):
    key_store.create_recipient_keypair(USER_A)

    other_key = base64.b64encode(b"\x07" * 32).decode("ascii")
    monkeypatch.setenv("QSHARE_MASTER_KEY", other_key)

    with pytest.raises(key_store.KeyStoreError):
        key_store.get_private_key(USER_A)


@pytest.mark.parametrize(
    "bad_value",
    [None, "not-base64!!", base64.b64encode(b"too-short").decode("ascii")],
)
def test_missing_or_invalid_master_key_is_rejected(monkeypatch, bad_value):
    if bad_value is None:
        monkeypatch.delenv("QSHARE_MASTER_KEY")
    else:
        monkeypatch.setenv("QSHARE_MASTER_KEY", bad_value)

    with pytest.raises(key_store.KeyStoreError):
        key_store.validate_master_key()
    with pytest.raises(key_store.KeyStoreError):
        key_store.create_recipient_keypair(USER_A)


def test_tampered_stored_key_is_rejected():
    key_store.create_recipient_keypair(USER_A)
    wrapped = bytearray(read_row(USER_A)["wrapped_private_key"])
    wrapped[0] ^= 1

    connection = sqlite3.connect(key_store.DATABASE_PATH)
    connection.execute(
        "UPDATE user_keys SET wrapped_private_key = ? WHERE user_id = ?",
        (bytes(wrapped), USER_A),
    )
    connection.commit()
    connection.close()

    with pytest.raises(key_store.KeyStoreError):
        key_store.get_private_key(USER_A)


def test_key_row_copied_to_another_user_is_rejected():
    key_store.create_recipient_keypair(USER_A)

    connection = sqlite3.connect(key_store.DATABASE_PATH)
    connection.execute(
        "UPDATE user_keys SET user_id = ? WHERE user_id = ?", (USER_B, USER_A)
    )
    connection.commit()
    connection.close()

    with pytest.raises(key_store.KeyStoreError):
        key_store.get_private_key(USER_B)