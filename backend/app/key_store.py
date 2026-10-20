"""Persistent, protected storage for each user's ML-KEM-768 key pair.

How it works (envelope encryption):
  * Each user's ML-KEM private key is encrypted with AES-256-GCM using a
    master key.
  * The master key (QSHARE_MASTER_KEY) lives in backend/.env, NOT in the
    database. The database only holds the ENCRYPTED private key.
  * The encryption is bound (through AAD) to the user and to the key row,
    so a stored key cannot be copied into another user's row.
  * A user can only ever have one active key pair. We never overwrite it,
    because that would make all of their old files unreadable.

Never log or return private keys or the master key.
"""

import base64
import binascii
import os
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = Path(os.getenv("QSHARE_KEYS_DB") or BASE_DIR / "qshare_keys.db")

ALGORITHM = "ML-KEM-768"
NONCE_SIZE = 12  # AES-GCM nonce, new random value for every stored key


class KeyStoreError(Exception):
    """The key store is misconfigured, or a stored key cannot be unlocked."""


class KeyAlreadyExistsError(Exception):
    """The user already has an active key pair (it is never overwritten)."""


# ---------------------------------------------------------------------------
# Master key (kept outside the database)
# ---------------------------------------------------------------------------
def _load_master_key() -> bytes:
    encoded = os.getenv("QSHARE_MASTER_KEY")
    if not encoded:
        raise KeyStoreError("QSHARE_MASTER_KEY is missing from backend/.env")

    try:
        master_key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise KeyStoreError("QSHARE_MASTER_KEY is not valid base64.") from error

    if len(master_key) != 32:
        raise KeyStoreError("QSHARE_MASTER_KEY must decode to exactly 32 bytes.")

    return master_key


def validate_master_key() -> None:
    """Call at startup so a missing or bad master key fails immediately."""
    _load_master_key()


def _aad(user_id: str, key_id: str) -> bytes:
    # Authenticated (but not secret) context: binds the encrypted key to
    # this user and this database row.
    return f"qshare:v1:{ALGORITHM}:{user_id}:{key_id}".encode("utf-8")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS user_keys (
            key_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            public_key BLOB NOT NULL,
            wrapped_private_key BLOB NOT NULL,
            nonce BLOB NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    # The database itself guarantees: at most ONE active key per user.
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS one_active_key_per_user
        ON user_keys (user_id) WHERE status = 'active'
        """
    )
    return connection


def _fetch_active_row(user_id: str):
    with closing(_connect()) as connection:
        return connection.execute(
            "SELECT * FROM user_keys WHERE user_id = ? AND status = 'active'",
            (user_id,),
        ).fetchone()


# ---------------------------------------------------------------------------
# Public functions (same names the rest of the app already uses)
# ---------------------------------------------------------------------------
def create_recipient_keypair(user_id: str) -> bytes:
    """Create and store a key pair. Returns the PUBLIC key bytes only."""
    master_key = _load_master_key()

    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    seed = private_key.private_bytes_raw()

    key_id = uuid.uuid4().hex
    nonce = os.urandom(NONCE_SIZE)
    wrapped = AESGCM(master_key).encrypt(nonce, seed, _aad(user_id, key_id))

    try:
        with closing(_connect()) as connection:
            with connection:  # commits on success
                connection.execute(
                    """
                    INSERT INTO user_keys (
                        key_id, user_id, algorithm, public_key,
                        wrapped_private_key, nonce, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
                    """,
                    (
                        key_id,
                        user_id,
                        ALGORITHM,
                        public_bytes,
                        wrapped,
                        nonce,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
    except sqlite3.IntegrityError as error:
        raise KeyAlreadyExistsError(
            "This user already has an active key pair."
        ) from error

    return public_bytes


def get_public_key(user_id: str) -> bytes | None:
    row = _fetch_active_row(user_id)
    return bytes(row["public_key"]) if row else None


def get_private_key(user_id: str) -> mlkem.MLKEM768PrivateKey | None:
    """Return the user's private key, or None if they have no key pair.

    Raises KeyStoreError if a key exists but cannot be unlocked (wrong
    master key, tampered data, or a row that belongs to someone else).
    """
    row = _fetch_active_row(user_id)
    if row is None:
        return None

    master_key = _load_master_key()

    try:
        seed = AESGCM(master_key).decrypt(
            bytes(row["nonce"]),
            bytes(row["wrapped_private_key"]),
            _aad(user_id, row["key_id"]),
        )
        private_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    except (InvalidTag, ValueError) as error:
        raise KeyStoreError("Stored private key could not be unlocked.") from error

    if private_key.public_key().public_bytes_raw() != bytes(row["public_key"]):
        raise KeyStoreError("Stored key pair is inconsistent.")

    return private_key