import base64
import binascii
import uuid

import jwt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem
from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr

from app.auth_service import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.crypto_service import decrypt_bytes, encrypt_bytes
from app.hybrid_crypto_service import decrypt_hybrid, encrypt_hybrid
from app.key_store import (
    create_recipient_keypair,
    get_private_key,
    get_public_key,
)
from app.user_store import create_user, find_user_by_email, find_user_by_id
from app.file_store import save_encrypted_file, list_user_files
from pathlib import Path
from urllib.parse import quote

from app.file_store import get_user_file

app = FastAPI(
    title="QShare API",
    description="Secure file-sharing research prototype",
    version="0.2.0",
)

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MiB prototype limit

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-Encryption-Key"],
)


# ---------------------------------------------------------------------------
# Authentication
# Keep this section above routes that use Depends(get_current_user).
# ---------------------------------------------------------------------------
security = HTTPBearer(auto_error=False)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = decode_access_token(credentials.credentials)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = find_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def decode_key(encoded_key: str) -> bytes:
    try:
        key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Encryption key must be valid Base64.",
        )

    if len(key) != 32:
        raise HTTPException(
            status_code=400,
            detail="Encryption key must decode to exactly 32 bytes.",
        )

    return key


async def read_limited_file(file: UploadFile) -> bytes:
    data = await file.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 25 MiB prototype limit.",
        )
    return data


# ---------------------------------------------------------------------------
# Account endpoints
# ---------------------------------------------------------------------------
@app.post("/api/auth/register", status_code=201)
def register_user(request: RegisterRequest):
    if len(request.password) < 12:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 12 characters.",
        )

    if find_user_by_email(str(request.email)):
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        )

    user_id = str(uuid.uuid4())
    password_digest = hash_password(request.password)

    try:
        create_user(user_id, str(request.email), password_digest)
    except Exception:
        # Handle a possible duplicate-email race without exposing DB details.
        if find_user_by_email(str(request.email)):
            raise HTTPException(
                status_code=409,
                detail="An account with this email already exists.",
            )
        raise

    return {
        "id": user_id,
        "email": str(request.email).lower(),
        "message": "Account created successfully.",
    }


@app.post("/api/auth/login")
def login_user(request: LoginRequest):
    user = find_user_by_email(str(request.email))
    if user is None or not verify_password(
        request.password, user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user["id"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 1800,
    }


@app.get("/api/auth/me")
def read_current_user(user=Depends(get_current_user)):
    return {
        "id": user["id"],
        "email": user["email"],
        "created_at": user["created_at"],
    }


# ---------------------------------------------------------------------------
# Basic service endpoints
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "project": "QShare",
        "message": "QShare API is running",
    }


@app.get("/api/health")
def health():
    return {
        "success": True,
        "service": "qshare-backend",
        "status": "healthy",
    }


# ---------------------------------------------------------------------------
# AES-256-GCM file encryption prototype
# ---------------------------------------------------------------------------
@app.post("/api/crypto/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    x_encryption_key: str = Header(...),
):
    key = decode_key(x_encryption_key)
    plaintext = await read_limited_file(file)
    nonce, ciphertext = encrypt_bytes(plaintext, key)

    # File format: 12-byte nonce || AES-GCM ciphertext and authentication tag.
    encrypted_payload = nonce + ciphertext
    return Response(
        content=encrypted_payload,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="qshare-encrypted.bin"',
            "X-Encryption-Format": "QSHARE-AES256GCM-V1",
        },
    )


@app.post("/api/crypto/decrypt")
async def decrypt_file(
    file: UploadFile = File(...),
    x_encryption_key: str = Header(...),
):
    key = decode_key(x_encryption_key)
    encrypted_payload = await read_limited_file(file)

    # 12-byte nonce plus at least a 16-byte GCM authentication tag.
    if len(encrypted_payload) < 28:
        raise HTTPException(
            status_code=400,
            detail="Invalid or incomplete encrypted file.",
        )

    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]
    try:
        plaintext = decrypt_bytes(ciphertext, key, nonce)
    except InvalidTag:
        raise HTTPException(
            status_code=400,
            detail="Decryption failed: wrong key or modified encrypted file.",
        )

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="qshare-decrypted.bin"',
        },
    )


# ---------------------------------------------------------------------------
# Authenticated hybrid ML-KEM-768 + AES-256-GCM endpoints
# ---------------------------------------------------------------------------
@app.post("/api/hybrid/keys/me")
def create_my_hybrid_keys(user=Depends(get_current_user)):
    public_key = create_recipient_keypair(user["id"])
    return {
        "algorithm": "ML-KEM-768",
        "public_key": base64.b64encode(public_key).decode("ascii"),
    }


@app.get("/api/hybrid/keys/me")
def read_my_hybrid_public_key(user=Depends(get_current_user)):
    public_key = get_public_key(user["id"])
    if public_key is None:
        raise HTTPException(
            status_code=404,
            detail="Create your key pair first.",
        )

    return {
        "algorithm": "ML-KEM-768",
        "public_key": base64.b64encode(public_key).decode("ascii"),
    }


@app.post("/api/hybrid/encrypt/me")
async def hybrid_encrypt_for_me(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    public_key_bytes = get_public_key(user["id"])
    if public_key_bytes is None:
        raise HTTPException(
            status_code=404,
            detail="Create your key pair first.",
        )

    try:
        public_key = mlkem.MLKEM768PublicKey.from_public_bytes(public_key_bytes)
        plaintext = await read_limited_file(file)
        payload = encrypt_hybrid(plaintext, public_key)
    except HTTPException:
        raise
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail="Hybrid encryption failed.",
        )

    return Response(
        content=payload,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="qshare-hybrid.bin"',
            "X-Encryption-Format": "QSHARE-HYBRID-MLKEM768-AES256GCM-V1",
        },
    )



@app.post("/api/files/encrypt")
async def encrypt_and_store_file(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    public_key_bytes = get_public_key(user["id"])

    if public_key_bytes is None:
        raise HTTPException(
            status_code=404,
            detail="Create your key pair first.",
        )

    try:
        plaintext = await read_limited_file(file)

        public_key = mlkem.MLKEM768PublicKey.from_public_bytes(
            public_key_bytes
        )

        encrypted_data = encrypt_hybrid(plaintext, public_key)

        metadata = save_encrypted_file(
            user_id=user["id"],
            original_name=file.filename or "file",
            original_size=len(plaintext),
            encrypted_data=encrypted_data,
        )

        return {
            "success": True,
            "message": "File encrypted and stored successfully.",
            "file": metadata,
        }

    except HTTPException:
        raise
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail="File encryption failed.",
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not store the encrypted file.",
        )
    finally:
        await file.close()


@app.get("/api/files")
async def get_my_files(user=Depends(get_current_user)):
    return {
        "files": list_user_files(user["id"])
    }


@app.get("/api/files/{file_id}/download")
async def download_my_file(
    file_id: str,
    user=Depends(get_current_user),
):
    record = get_user_file(user["id"], file_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="File not found.",
        )

    private_key = get_private_key(user["id"])

    if private_key is None:
        raise HTTPException(
            status_code=404,
            detail="Your decryption key is unavailable.",
        )

    try:
        encrypted_data = record["path"].read_bytes()
        plaintext = decrypt_hybrid(encrypted_data, private_key)
    except (ValueError, InvalidTag):
        raise HTTPException(
            status_code=400,
            detail="Decryption failed: invalid or modified file.",
        )
    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Could not read the stored file.",
        )

    filename = Path(record["name"]).name or "download.bin"

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f"attachment; filename*=UTF-8''{quote(filename)}"
            ),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.post("/api/hybrid/decrypt/me")
async def hybrid_decrypt_for_me(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    private_key = get_private_key(user["id"])
    if private_key is None:
        raise HTTPException(
            status_code=404,
            detail="Create your key pair first.",
        )

    payload = await read_limited_file(file)
    try:
        plaintext = decrypt_hybrid(payload, private_key)
    except (ValueError, InvalidTag):
        raise HTTPException(
            status_code=400,
            detail="Decryption failed: invalid, modified, or incompatible file.",
        )

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="qshare-decrypted.bin"',
        },
    )
