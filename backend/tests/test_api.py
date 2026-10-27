"""Tests for the basic AES-256-GCM prototype endpoints.

These endpoints now require a login, so each test registers a fresh user.
"""

import base64
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.crypto_service import generate_key

client = TestClient(app)

PASSWORD = "QShare-Test-Password-2026!"


def auth_headers():
    """Register and log in a fresh user; return the Authorization header."""
    email = f"api-{uuid.uuid4().hex}@example.com"
    registered = client.post(
        "/api/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert registered.status_code == 201, registered.text
    login = client.post(
        "/api/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def encoded_key():
    return base64.b64encode(generate_key()).decode("ascii")


def test_health_endpoint():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_encrypt_then_decrypt_file():
    auth = auth_headers()
    key = encoded_key()
    original = b"QShare API encryption test."

    encrypted = client.post(
        "/api/crypto/encrypt",
        headers={**auth, "X-Encryption-Key": key},
        files={"file": ("test.txt", original, "text/plain")},
    )

    assert encrypted.status_code == 200
    assert encrypted.content != original
    assert encrypted.headers["x-encryption-format"] == (
        "QSHARE-AES256GCM-V1"
    )

    decrypted = client.post(
        "/api/crypto/decrypt",
        headers={**auth, "X-Encryption-Key": key},
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
    auth = auth_headers()
    key = encoded_key()

    encrypted = client.post(
        "/api/crypto/encrypt",
        headers={**auth, "X-Encryption-Key": key},
        files={"file": ("test.txt", b"Sensitive test data", "text/plain")},
    )

    assert encrypted.status_code == 200

    tampered = bytearray(encrypted.content)
    tampered[-1] ^= 1

    response = client.post(
        "/api/crypto/decrypt",
        headers={**auth, "X-Encryption-Key": key},
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
    auth = auth_headers()
    key1 = encoded_key()
    key2 = encoded_key()

    encrypted = client.post(
        "/api/crypto/encrypt",
        headers={**auth, "X-Encryption-Key": key1},
        files={"file": ("test.txt", b"Private data", "text/plain")},
    )

    response = client.post(
        "/api/crypto/decrypt",
        headers={**auth, "X-Encryption-Key": key2},
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
        headers={**auth_headers(), "X-Encryption-Key": "not-valid-base64!"},
        files={"file": ("test.txt", b"test", "text/plain")},
    )

    assert response.status_code == 400