
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def create_recipient(recipient_id: str) -> None:
    response = client.post(f"/api/hybrid/keys/{recipient_id}")
    assert response.status_code == 200
    assert response.json()["algorithm"] == "ML-KEM-768"


def test_create_and_get_recipient_public_key():
    recipient_id = "api-test-recipient"
    create_recipient(recipient_id)

    response = client.get(f"/api/hybrid/keys/{recipient_id}")

    assert response.status_code == 200
    result = response.json()
    assert result["recipient_id"] == recipient_id
    assert result["algorithm"] == "ML-KEM-768"
    assert len(result["public_key"]) > 0


def test_hybrid_file_encrypt_decrypt():
    recipient_id = "roundtrip-recipient"
    original = b"QShare hybrid API integration test."

    create_recipient(recipient_id)

    encrypted = client.post(
        f"/api/hybrid/encrypt/{recipient_id}",
        files={"file": ("sample.txt", original, "text/plain")},
    )

    assert encrypted.status_code == 200
    assert encrypted.content != original
    assert (
        encrypted.headers["x-encryption-format"]
        == "QSHARE-HYBRID-MLKEM768-AES256GCM-V1"
    )

    decrypted = client.post(
        f"/api/hybrid/decrypt/{recipient_id}",
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


def test_modified_hybrid_file_is_rejected():
    recipient_id = "tamper-test-recipient"
    create_recipient(recipient_id)

    encrypted = client.post(
        f"/api/hybrid/encrypt/{recipient_id}",
        files={"file": ("sample.txt", b"Confidential data", "text/plain")},
    )
    assert encrypted.status_code == 200

    tampered = bytearray(encrypted.content)
    tampered[-1] ^= 1

    response = client.post(
        f"/api/hybrid/decrypt/{recipient_id}",
        files={
            "file": (
                "tampered.bin",
                bytes(tampered),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 400


def test_unknown_recipient_cannot_encrypt():
    response = client.post(
        "/api/hybrid/encrypt/unknown-recipient",
        files={"file": ("sample.txt", b"test", "text/plain")},
    )

    assert response.status_code == 404


def test_unknown_recipient_cannot_decrypt():
    response = client.post(
        "/api/hybrid/decrypt/unknown-recipient",
        files={
            "file": (
                "encrypted.bin",
                b"invalid payload",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 404
