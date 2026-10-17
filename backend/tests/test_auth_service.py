
import time

import jwt
import pytest

from app.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)


def test_password_hash_and_verify():
    password = "QShare-Test-Password-2026!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("wrong-password", hashed)


def test_short_password_rejected():
    with pytest.raises(ValueError):
        hash_password("short")


def test_access_token_roundtrip():
    token = create_access_token("user-123")
    assert decode_access_token(token) == "user-123"


def test_invalid_token_rejected():
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token("not.a.valid.token")


def test_expired_token_rejected():
    token = jwt.encode(
        {"sub": "user-123", "exp": int(time.time()) - 60},
        __import__("app.auth_service", fromlist=["JWT_SECRET_KEY"]).JWT_SECRET_KEY,
        algorithm="HS256",
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)
