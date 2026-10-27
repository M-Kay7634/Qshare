"""Tests for deleting files, and for the clear 'lost key' message."""

import io
import sqlite3
import time
import uuid

from fastapi.testclient import TestClient

from app import file_store, key_store
from app.main import app

client = TestClient(app)

PASSWORD = "QShare-Test-Password-2026!"


def make_user_headers(prefix="del"):
    email = f"{prefix}-{uuid.uuid4().hex}@example.com"
    registered = client.post(
        "/api/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert registered.status_code == 201, registered.text
    login = client.post(
        "/api/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def upload(headers, content: bytes, name="note.txt"):
    """Create a key pair if needed, upload one file, return its file id."""
    if client.get("/api/hybrid/keys/me", headers=headers).status_code == 404:
        keys = client.post("/api/hybrid/keys/me", headers=headers)
        assert keys.status_code == 200, keys.text
    response = client.post(
        "/api/files/encrypt",
        headers=headers,
        files={"file": (name, io.BytesIO(content), "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()["file"]["id"]


def stored_files():
    return list(file_store.STORAGE_DIR.glob("*.qsf"))


def test_delete_requires_login():
    assert client.delete("/api/files/anything").status_code == 401


def test_delete_own_file_removes_record_and_encrypted_file():
    headers = make_user_headers()
    file_id = upload(headers, b"please delete me")
    assert len(stored_files()) == 1

    response = client.delete(f"/api/files/{file_id}", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["success"] is True

    assert client.get("/api/files", headers=headers).json()["files"] == []
    assert stored_files() == []
    after = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert after.status_code == 404


def test_other_user_cannot_delete_my_file():
    owner = make_user_headers("owner")
    other = make_user_headers("other")
    file_id = upload(owner, b"keep me")

    response = client.delete(f"/api/files/{file_id}", headers=other)
    assert response.status_code == 404

    # The owner still has the file and can still read it.
    download = client.get(f"/api/files/{file_id}/download", headers=owner)
    assert download.status_code == 200, download.text
    assert download.content == b"keep me"
    assert len(stored_files()) == 1


def test_deleting_an_unknown_file_returns_404():
    headers = make_user_headers()
    response = client.delete(f"/api/files/{uuid.uuid4()}", headers=headers)
    assert response.status_code == 404


def test_delete_still_works_if_the_encrypted_file_is_already_missing():
    headers = make_user_headers()
    file_id = upload(headers, b"orphan record")
    for path in stored_files():
        path.unlink()

    response = client.delete(f"/api/files/{file_id}", headers=headers)
    assert response.status_code == 200, response.text
    assert client.get("/api/files", headers=headers).json()["files"] == []


def test_file_from_before_the_current_key_gets_a_clear_message():
    headers = make_user_headers()
    file_id = upload(headers, b"encrypted with an old key")

    # Simulate the old key being lost: remove it, then get a brand-new key.
    connection = sqlite3.connect(key_store.DATABASE_PATH)
    connection.execute("DELETE FROM user_keys")
    connection.commit()
    connection.close()
    time.sleep(0.05)
    assert client.post("/api/hybrid/keys/me", headers=headers).status_code == 200

    download = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert download.status_code == 410
    assert "no longer exists" in download.json()["detail"]

    # The user can clean it up.
    assert client.delete(f"/api/files/{file_id}", headers=headers).status_code == 200


def test_modified_new_file_still_says_modified_not_lost_key():
    headers = make_user_headers()
    file_id = upload(headers, b"tamper with me")

    path = stored_files()[0]
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))

    download = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert download.status_code == 400
    assert "invalid or modified" in download.json()["detail"]


def test_file_with_no_key_at_all_gets_the_same_clear_message():
    headers = make_user_headers()
    file_id = upload(headers, b"its key is gone completely")

    # The key is lost and the user has not made a new one yet.
    connection = sqlite3.connect(key_store.DATABASE_PATH)
    connection.execute("DELETE FROM user_keys")
    connection.commit()
    connection.close()

    download = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert download.status_code == 410
    assert "no longer exists" in download.json()["detail"]