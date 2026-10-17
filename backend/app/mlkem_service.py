
from cryptography.hazmat.primitives.asymmetric import mlkem


def generate_keypair():
    """Generate an ML-KEM-768 key pair."""
    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()
    return public_key, private_key


def encapsulate_secret(public_key):
    """Generate a shared secret and its encapsulation ciphertext."""
    return public_key.encapsulate()


def decapsulate_secret(private_key, ciphertext: bytes) -> bytes:
    """Recover the shared secret using the private key."""
    return private_key.decapsulate(ciphertext)
