
import io
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.fixture
def auth_headers():
    """Register a unique test account and return its bearer token."""
    email = f"hybrid-{uuid.uuid4().hex}@example.com"
    password = "QShare-Test-Password-2026!"

    register_response = client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
    )
    assert register_response.status_code == 201, register_response.text

    login_response = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def create_my_keys(headers):
    response = client.post("/api/hybrid/keys/me", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["algorithm"] == "ML-KEM-768"
    assert response.json()["public_key"]
    return response.json()["public_key"]


def test_hybrid_endpoints_require_authentication():
    response = client.post("/api/hybrid/keys/me")
    assert response.status_code == 401

    response = client.get("/api/hybrid/keys/me")
    assert response.status_code == 401


def test_create_and_get_recipient_public_key(auth_headers):
    created = create_my_keys(auth_headers)

    response = client.get("/api/hybrid/keys/me", headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()["algorithm"] == "ML-KEM-768"
    assert response.json()["public_key"] == created


def test_hybrid_file_encrypt_decrypt(auth_headers):
    create_my_keys(auth_headers)
    original = b"QShare hybrid API integration test."

    encrypt_response = client.post(
        "/api/hybrid/encrypt/me",
        headers=auth_headers,
        files={"file": ("original.txt", io.BytesIO(original), "text/plain")},
    )
    assert encrypt_response.status_code == 200, encrypt_response.text

    encrypted_payload = encrypt_response.content
    assert encrypted_payload != original
    assert encrypted_payload

    decrypt_response = client.post(
        "/api/hybrid/decrypt/me",
        headers=auth_headers,
        files={
            "file": (
                "encrypted.bin",
                io.BytesIO(encrypted_payload),
                "application/octet-stream",
            )
        },
    )
    assert decrypt_response.status_code == 200, decrypt_response.text
    assert decrypt_response.content == original


def test_modified_hybrid_file_is_rejected(auth_headers):
    create_my_keys(auth_headers)
    original = b"Tamper detection test for QShare."

    encrypt_response = client.post(
        "/api/hybrid/encrypt/me",
        headers=auth_headers,
        files={"file": ("original.txt", io.BytesIO(original), "text/plain")},
    )
    assert encrypt_response.status_code == 200, encrypt_response.text

    modified = bytearray(encrypt_response.content)
    modified[-1] ^= 1

    decrypt_response = client.post(
        "/api/hybrid/decrypt/me",
        headers=auth_headers,
        files={
            "file": (
                "modified.bin",
                io.BytesIO(bytes(modified)),
                "application/octet-stream",
            )
        },
    )
    assert decrypt_response.status_code == 400


def test_hybrid_key_and_file_operations_are_user_scoped(auth_headers):
    create_my_keys(auth_headers)

    other_email = f"other-{uuid.uuid4().hex}@example.com"
    password = "Another-QShare-Password-2026!"

    register_response = client.post(
        "/api/auth/register",
        json={"email": other_email, "password": password},
    )
    assert register_response.status_code == 201, register_response.text

    login_response = client.post(
        "/api/auth/login",
        json={"email": other_email, "password": password},
    )
    assert login_response.status_code == 200, login_response.text
    other_headers = {
        "Authorization": f"Bearer {login_response.json()['access_token']}"
    }

    # A different account must not see the first account's key.
    response = client.get("/api/hybrid/keys/me", headers=other_headers)
    assert response.status_code == 404

    # A different account cannot decrypt a file encrypted for the first account.
    original = b"Private test content."
    encrypted = client.post(
        "/api/hybrid/encrypt/me",
        headers=auth_headers,
        files={"file": ("original.txt", io.BytesIO(original), "text/plain")},
    )
    assert encrypted.status_code == 200, encrypted.text

    decrypt = client.post(
        "/api/hybrid/decrypt/me",
        headers=other_headers,
        files={
            "file": (
                "encrypted.bin",
                io.BytesIO(encrypted.content),
                "application/octet-stream",
            )
        },
    )
    assert decrypt.status_code in (400, 404)
