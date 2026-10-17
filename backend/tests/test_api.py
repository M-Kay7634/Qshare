
import base64

from fastapi.testclient import TestClient

from app.main import app
from app.crypto_service import generate_key

client = TestClient(app)


def encoded_key():
    return base64.b64encode(generate_key()).decode("ascii")


def test_health_endpoint():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_encrypt_then_decrypt_file():
    key = encoded_key()
    original = b"QShare API encryption test."

    encrypted = client.post(
        "/api/crypto/encrypt",
        headers={"X-Encryption-Key": key},
        files={"file": ("test.txt", original, "text/plain")},
    )

    assert encrypted.status_code == 200
    assert encrypted.content != original
    assert encrypted.headers["x-encryption-format"] == (
        "QSHARE-AES256GCM-V1"
    )

    decrypted = client.post(
        "/api/crypto/decrypt",
        headers={"X-Encryption-Key": key},
        files={
            "file": (
                "encrypted.bin",
                encrypted.content,
                "application/octet-stream",
            )
        },
    )

    assert decrypted.status_code == 200
    assert decrypted.content == original


def test_modified_ciphertext_is_rejected():
    key = encoded_key()

    encrypted = client.post(
        "/api/crypto/encrypt",
        headers={"X-Encryption-Key": key},
        files={"file": ("test.txt", b"Sensitive test data", "text/plain")},
    )

    assert encrypted.status_code == 200

    tampered = bytearray(encrypted.content)
    tampered[-1] ^= 1

    response = client.post(
        "/api/crypto/decrypt",
        headers={"X-Encryption-Key": key},
        files={
            "file": (
                "tampered.bin",
                bytes(tampered),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 400
    assert "Decryption failed" in response.json()["detail"]


def test_wrong_key_is_rejected():
    key1 = encoded_key()
    key2 = encoded_key()

    encrypted = client.post(
        "/api/crypto/encrypt",
        headers={"X-Encryption-Key": key1},
        files={"file": ("test.txt", b"Private data", "text/plain")},
    )

    response = client.post(
        "/api/crypto/decrypt",
        headers={"X-Encryption-Key": key2},
        files={
            "file": (
                "encrypted.bin",
                encrypted.content,
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 400


def test_invalid_key_is_rejected():
    response = client.post(
        "/api/crypto/encrypt",
        headers={"X-Encryption-Key": "not-valid-base64!"},
        files={"file": ("test.txt", b"test", "text/plain")},
    )

    assert response.status_code == 400
