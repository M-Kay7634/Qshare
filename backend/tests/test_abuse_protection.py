"""Tests for the abuse protections in app/main.py (Task 10)."""

import base64
import io
import uuid

import pytest
from fastapi.testclient import TestClient

from app import file_store, limits, main
from app.body_limit import TOO_LARGE_DETAIL
from app.crypto_service import generate_key
from app.main import MAX_FILE_SIZE, MAX_PASSWORD_LENGTH, app

client = TestClient(app)

GOOD = "QShare-Test-Password-2026!"
WRONG = "definitely-not-the-password"
ORIGIN = "http://localhost:5173"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch):
    clock = FakeClock()
    for limiter in limits.ALL:
        monkeypatch.setattr(limiter, "clock", clock)
    return clock


def register(email=None, password=GOOD):
    email = email or f"abuse-{uuid.uuid4().hex}@example.com"
    response = client.post(
        "/api/auth/register", json={"email": email, "password": password}
    )
    return email, response


def login(email, password):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def auth_headers():
    email, response = register()
    assert response.status_code == 201, response.text
    token = login(email, GOOD).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# --- login lockout ---------------------------------------------------------------
def test_five_wrong_passwords_lock_the_account_even_for_the_right_password(fake_clock):
    email, _ = register()
    for _ in range(5):
        assert login(email, WRONG).status_code == 401

    locked = login(email, GOOD)

    assert locked.status_code == 429
    assert "Too many failed login attempts" in locked.json()["detail"]
    assert 1 <= int(locked.headers["Retry-After"]) <= 15 * 60

    fake_clock.advance(15 * 60 + 1)
    assert login(email, GOOD).status_code == 200


def test_a_successful_login_resets_the_failure_count(fake_clock):
    email, _ = register()
    for _ in range(4):
        assert login(email, WRONG).status_code == 401
    assert login(email, GOOD).status_code == 200
    for _ in range(4):
        assert login(email, WRONG).status_code == 401
    assert login(email, GOOD).status_code == 200


def test_unknown_emails_are_locked_out_the_same_way(fake_clock):
    ghost = f"ghost-{uuid.uuid4().hex}@example.com"
    for _ in range(5):
        assert login(ghost, WRONG).status_code == 401
    assert login(ghost, WRONG).status_code == 429  # same behavior: nothing is revealed


def test_spraying_many_accounts_from_one_address_is_stopped(fake_clock):
    for number in range(30):
        assert login(f"nobody{number}@example.com", WRONG).status_code == 401

    response = login("someone-new@example.com", WRONG)

    assert response.status_code == 429


def test_an_unknown_email_still_costs_one_password_check(monkeypatch):
    digests = []
    real = main.verify_password

    def spy(password, digest):
        digests.append(digest)
        return real(password, digest)

    monkeypatch.setattr(main, "verify_password", spy)

    login(f"ghost-{uuid.uuid4().hex}@example.com", WRONG)
    assert digests == [main.TIMING_DUMMY_DIGEST]

    email, _ = register()
    digests.clear()
    login(email, WRONG)
    assert len(digests) == 1 and digests[0] != main.TIMING_DUMMY_DIGEST


def test_a_huge_password_is_refused_without_being_hashed(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "verify_password", lambda *args: calls.append(args) or True)
    email, _ = register()

    response = login(email, "x" * (MAX_PASSWORD_LENGTH + 1))

    assert response.status_code == 401
    assert calls == []


# --- registration --------------------------------------------------------------------
def test_password_length_rules_on_registration():
    assert register(password="short-11-ch")[1].status_code == 400
    assert "at least 12" in register(password="short-11-ch")[1].json()["detail"]

    assert register(password="p" * MAX_PASSWORD_LENGTH)[1].status_code == 201
    too_long = register(password="p" * (MAX_PASSWORD_LENGTH + 1))[1]
    assert too_long.status_code == 400
    assert "at most 128" in too_long.json()["detail"]


def test_too_many_new_accounts_from_one_address_are_refused(fake_clock):
    for _ in range(10):
        assert register()[1].status_code == 201

    response = register()[1]

    assert response.status_code == 429
    assert "Too many new accounts" in response.json()["detail"]
    fake_clock.advance(60 * 60 + 1)
    assert register()[1].status_code == 201


# --- expensive endpoints ------------------------------------------------------------------
def test_the_prototype_crypto_endpoints_now_need_a_login():
    key = base64.b64encode(generate_key()).decode("ascii")
    files = {"file": ("test.txt", b"data", "text/plain")}

    for path in ("/api/crypto/encrypt", "/api/crypto/decrypt"):
        response = client.post(path, headers={"X-Encryption-Key": key}, files=files)
        assert response.status_code == 401


def test_prototype_crypto_calls_are_rate_limited(fake_clock):
    headers = {**auth_headers(),
               "X-Encryption-Key": base64.b64encode(generate_key()).decode("ascii")}

    def call():
        return client.post("/api/crypto/encrypt", headers=headers,
                           files={"file": ("t.txt", b"data", "text/plain")})

    for _ in range(30):
        assert call().status_code == 200
    assert call().status_code == 429
    fake_clock.advance(61)
    assert call().status_code == 200


def test_uploads_are_rate_limited_per_user(fake_clock):
    headers = auth_headers()
    assert client.post("/api/hybrid/keys/me", headers=headers).status_code == 200

    def upload():
        return client.post("/api/files/encrypt", headers=headers,
                           files={"file": ("n.txt", io.BytesIO(b"hello"), "text/plain")})

    for _ in range(30):
        assert upload().status_code == 200
    limited = upload()
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1

    other_user = auth_headers()  # someone else is not affected
    assert client.post("/api/hybrid/keys/me", headers=other_user).status_code == 200
    assert client.post("/api/files/encrypt", headers=other_user,
                       files={"file": ("n.txt", b"hi", "text/plain")}).status_code == 200

    fake_clock.advance(61)
    assert upload().status_code == 200


# --- oversized bodies ------------------------------------------------------------------------
def test_a_huge_upload_is_refused_before_anything_is_stored():
    headers = auth_headers()
    assert client.post("/api/hybrid/keys/me", headers=headers).status_code == 200
    huge = b"\0" * (MAX_FILE_SIZE + 2 * 1024 * 1024)

    response = client.post("/api/files/encrypt", headers=headers,
                           files={"file": ("big.bin", huge, "application/octet-stream")})

    assert response.status_code == 413
    assert response.json() == {"detail": TOO_LARGE_DETAIL}
    assert client.get("/api/files", headers=headers).json()["files"] == []
    assert list(file_store.STORAGE_DIR.glob("*.qsf")) == []


def test_a_file_just_over_the_app_limit_still_gets_the_file_message():
    headers = auth_headers()
    assert client.post("/api/hybrid/keys/me", headers=headers).status_code == 200
    slightly_over = b"\0" * (MAX_FILE_SIZE + 1)

    response = client.post("/api/files/encrypt", headers=headers,
                           files={"file": ("big.bin", slightly_over, "application/octet-stream")})

    assert response.status_code == 413
    assert "25 MiB" in response.json()["detail"]


# --- browsers must still be able to read the error ---------------------------------------------
def test_error_responses_still_carry_cors_headers(fake_clock):
    email, _ = register()
    for _ in range(5):
        login(email, WRONG)

    locked = client.post("/api/auth/login", json={"email": email, "password": GOOD},
                         headers={"Origin": ORIGIN})
    assert locked.status_code == 429
    assert locked.headers["access-control-allow-origin"] == ORIGIN

    headers = {**auth_headers(), "Origin": ORIGIN}
    assert client.post("/api/hybrid/keys/me", headers=headers).status_code == 200
    too_big = client.post("/api/files/encrypt", headers=headers,
                          files={"file": ("b.bin", b"\0" * (MAX_FILE_SIZE + 2 * 1024 * 1024),
                                          "application/octet-stream")})
    assert too_big.status_code == 413
    assert too_big.headers["access-control-allow-origin"] == ORIGIN