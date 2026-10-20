"""Tests for the stored-file workflow: upload -> list -> download.

The restart test reproduces the known bug: after the backend restarts,
the in-memory private key is gone and old files cannot be downloaded.
"""

import io
import uuid

import pytest
from fastapi.testclient import TestClient

from app import key_store
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


def simulate_backend_restart():
    """A restart empties everything held in memory, including keys."""
    key_store._PRIVATE_KEYS.clear()
    key_store._PUBLIC_KEYS.clear()


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


@pytest.mark.xfail(
    strict=True,
    reason="KNOWN BUG: private keys live only in memory (key_store.py). "
    "Remove this marker once persistent key storage is implemented.",
)
def test_file_still_downloads_after_backend_restart():
    headers = make_user_headers()
    original = b"This file must survive a backend restart."
    file_id = upload(headers, original)

    simulate_backend_restart()

    download = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert download.status_code == 200, download.text
    assert download.content == original