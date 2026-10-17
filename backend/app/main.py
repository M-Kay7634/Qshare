
import base64
import binascii

from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from app.crypto_service import encrypt_bytes, decrypt_bytes

app = FastAPI(
    title="QShare API",
    description="Secure file-sharing research prototype",
    version="0.2.0",
)

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MiB for this initial API


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-Encryption-Key"],
)


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


@app.post("/api/crypto/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    x_encryption_key: str = Header(...),
):
    key = decode_key(x_encryption_key)
    plaintext = await read_limited_file(file)

    nonce, ciphertext = encrypt_bytes(plaintext, key)

    # Prototype file format: 12-byte nonce || ciphertext || GCM tag.
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

    # A 12-byte nonce and a 16-byte GCM tag are required.
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
