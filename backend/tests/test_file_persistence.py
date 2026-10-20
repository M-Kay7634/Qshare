"""Tests for the stored-file workflow: upload -> list -> download.

The real "restart" test lives in test_key_store.py (it starts a new Python
process). These tests check the same behavior through the API.
"""

import io
import uuid

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

PASSWORD = "QShare-Test-Password-2026!"


def make_user_headers(prefix="files"):
    """Register + log in a unique test user and return auth headers."""
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
    """Create a key pair, upload one file, return its file id."""
    keys = client.post("/api/hybrid/keys/me", headers=headers)
    assert keys.status_code == 200, keys.text
    response = client.post(
        "/api/files/encrypt",
        headers=headers,
        files={"file": (name, io.BytesIO(content), "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()["file"]["id"]


def test_upload_list_download_round_trip():
    headers = make_user_headers()
    original = b"QShare stored-file round trip."
    file_id = upload(headers, original)

    listing = client.get("/api/files", headers=headers)
    assert listing.status_code == 200, listing.text
    assert [f["id"] for f in listing.json()["files"]] == [file_id]

    download = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert download.status_code == 200, download.text
    assert download.content == original


def test_other_user_cannot_see_or_download_my_file():
    owner = make_user_headers("owner")
    other = make_user_headers("other")
    file_id = upload(owner, b"Private to the owner.")

    listing = client.get("/api/files", headers=other)
    assert listing.status_code == 200, listing.text
    assert listing.json()["files"] == []

    download = client.get(f"/api/files/{file_id}/download", headers=other)
    assert download.status_code == 404


def test_creating_a_second_key_is_refused_and_old_file_still_downloads():
    headers = make_user_headers()
    original = b"This file must stay readable."
    file_id = upload(headers, original)

    again = client.post("/api/hybrid/keys/me", headers=headers)
    assert again.status_code == 409, again.text

    download = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert download.status_code == 200, download.text
    assert download.content == original


def test_key_problems_return_a_generic_error_not_details(monkeypatch):
    headers = make_user_headers()
    file_id = upload(headers, b"secret")

    import base64

    monkeypatch.setenv("QSHARE_MASTER_KEY", base64.b64encode(b"\x09" * 32).decode())

    download = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert download.status_code == 500
    assert download.json() == {
        "detail": "The server could not access your encryption key."
    }