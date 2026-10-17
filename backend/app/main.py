
import base64
import binascii

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem
from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from app.crypto_service import encrypt_bytes, decrypt_bytes

from app.key_store import (
    create_recipient_keypair,
    get_public_key,
    get_private_key,
)
from app.hybrid_crypto_service import encrypt_hybrid, decrypt_hybrid

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



from fastapi import Body
from fastapi.responses import Response


@app.post("/api/hybrid/keys/{recipient_id}")
def create_hybrid_keys(recipient_id: str):
    if not recipient_id or len(recipient_id) > 100:
        raise HTTPException(status_code=400, detail="Invalid recipient ID.")

    public_key = create_recipient_keypair(recipient_id)
    return {
        "recipient_id": recipient_id,
        "algorithm": "ML-KEM-768",
        "public_key": base64.b64encode(public_key).decode("ascii"),
    }


@app.get("/api/hybrid/keys/{recipient_id}")
def read_hybrid_public_key(recipient_id: str):
    public_key = get_public_key(recipient_id)
    if public_key is None:
        raise HTTPException(status_code=404, detail="Recipient key not found.")

    return {
        "recipient_id": recipient_id,
        "algorithm": "ML-KEM-768",
        "public_key": base64.b64encode(public_key).decode("ascii"),
    }


@app.post("/api/hybrid/encrypt/{recipient_id}")
async def hybrid_encrypt_file(
    recipient_id: str,
    file: UploadFile = File(...),
):
    public_key_bytes = get_public_key(recipient_id)
    if public_key_bytes is None:
        raise HTTPException(status_code=404, detail="Recipient key not found.")

    try:
        public_key = mlkem.MLKEM768PublicKey.from_public_bytes(
            public_key_bytes
        )
        plaintext = await read_limited_file(file)
        payload = encrypt_hybrid(plaintext, public_key)
    except HTTPException:
        raise
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Hybrid encryption failed.")

    return Response(
        content=payload,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="qshare-hybrid.bin"',
            "X-Encryption-Format": "QSHARE-HYBRID-MLKEM768-AES256GCM-V1",
        },
    )


@app.post("/api/hybrid/decrypt/{recipient_id}")
async def hybrid_decrypt_file(
    recipient_id: str,
    file: UploadFile = File(...),
):
    private_key = get_private_key(recipient_id)
    if private_key is None:
        raise HTTPException(status_code=404, detail="Recipient private key not found.")

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
