
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MAGIC = b"QSHARE01"
KEM_CIPHERTEXT_SIZE = 1088
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
AES_KEY_SIZE = 32

HKDF_INFO = b"QShare hybrid file encryption v1"


def derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the ML-KEM shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


def encrypt_hybrid(
    plaintext: bytes,
    recipient_public_key: mlkem.MLKEM768PublicKey,
) -> bytes:
    """Encrypt bytes using ML-KEM-768, HKDF-SHA-256 and AES-256-GCM."""
    shared_secret, kem_ciphertext = recipient_public_key.encapsulate()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    aes_key = derive_aes_key(shared_secret, salt)

    # The header is authenticated along with the encrypted content.
    header = MAGIC + kem_ciphertext + salt + nonce
    encrypted_content = AESGCM(aes_key).encrypt(
        nonce, plaintext, header
    )

    return header + encrypted_content


def decrypt_hybrid(
    payload: bytes,
    recipient_private_key: mlkem.MLKEM768PrivateKey,
) -> bytes:
    """Decrypt a hybrid payload using the recipient's private key."""
    header_size = (
        len(MAGIC)
        + KEM_CIPHERTEXT_SIZE
        + SALT_SIZE
        + NONCE_SIZE
    )

    if len(payload) < header_size + TAG_SIZE:
        raise ValueError("Encrypted payload is incomplete.")

    if payload[:len(MAGIC)] != MAGIC:
        raise ValueError("Unrecognized QShare encrypted-file format.")

    offset = len(MAGIC)
    kem_ciphertext = payload[offset:offset + KEM_CIPHERTEXT_SIZE]
    offset += KEM_CIPHERTEXT_SIZE

    salt = payload[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    header = payload[:offset]
    encrypted_content = payload[offset:]

    shared_secret = recipient_private_key.decapsulate(kem_ciphertext)
    aes_key = derive_aes_key(shared_secret, salt)

    try:
        return AESGCM(aes_key).decrypt(
            nonce, encrypted_content, header
        )
    except InvalidTag:
        raise InvalidTag("Decryption failed: wrong key or modified payload.")
