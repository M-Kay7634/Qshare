
from cryptography.hazmat.primitives.asymmetric import mlkem

# Temporary in-memory storage for local development only.
_PRIVATE_KEYS: dict[str, mlkem.MLKEM768PrivateKey] = {}
_PUBLIC_KEYS: dict[str, mlkem.MLKEM768PublicKey] = {}


def create_recipient_keypair(recipient_id: str) -> bytes:
    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()

    _PRIVATE_KEYS[recipient_id] = private_key
    _PUBLIC_KEYS[recipient_id] = public_key

    return public_key.public_bytes_raw()


def get_public_key(recipient_id: str) -> bytes | None:
    public_key = _PUBLIC_KEYS.get(recipient_id)
    return public_key.public_bytes_raw() if public_key else None


def get_private_key(
    recipient_id: str,
) -> mlkem.MLKEM768PrivateKey | None:
    return _PRIVATE_KEYS.get(recipient_id)
