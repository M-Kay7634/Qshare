
import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from pwdlib import PasswordHash

load_dotenv()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing from backend/.env")

JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> str:
    payload = jwt.decode(
        token,
        JWT_SECRET_KEY,
        algorithms=[JWT_ALGORITHM],
    )
    user_id = payload.get("sub")
    if not isinstance(user_id, str) or not user_id:
        raise jwt.InvalidTokenError("Invalid token subject")
    return user_id
