
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage" / "encrypted"
DATABASE_PATH = BASE_DIR / "qshare_files.db"

STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_file_store():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                encrypted_name TEXT NOT NULL UNIQUE,
                original_size INTEGER NOT NULL,
                encrypted_size INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def save_encrypted_file(
    user_id,
    original_name,
    original_size,
    encrypted_data,
):
    file_id = str(uuid.uuid4())
    encrypted_name = f"{file_id}.qsf"
    destination = STORAGE_DIR / encrypted_name

    created_at = datetime.now(timezone.utc).isoformat()

    try:
        with destination.open("xb") as output:
            output.write(encrypted_data)

        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO encrypted_files (
                    id, user_id, original_name, encrypted_name,
                    original_size, encrypted_size, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    str(user_id),
                    Path(original_name or "file").name,
                    encrypted_name,
                    original_size,
                    len(encrypted_data),
                    created_at,
                ),
            )
    except Exception:
        destination.unlink(missing_ok=True)
        raise

    return {
        "id": file_id,
        "name": Path(original_name or "file").name,
        "original_size": original_size,
        "encrypted_size": len(encrypted_data),
        "created_at": created_at,
        "status": "encrypted",
    }


def list_user_files(user_id):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, original_name, original_size,
                   encrypted_size, created_at
            FROM encrypted_files
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (str(user_id),),
        ).fetchall()

    return [
        {
            "id": row["id"],
            "name": row["original_name"],
            "original_size": row["original_size"],
            "encrypted_size": row["encrypted_size"],
            "created_at": row["created_at"],
            "status": "encrypted",
        }
        for row in rows
    ]



def get_user_file(user_id, file_id):
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, user_id, original_name, encrypted_name,
                   original_size, encrypted_size, created_at
            FROM encrypted_files
            WHERE id = ? AND user_id = ?
            """,
            (file_id, str(user_id)),
        ).fetchone()

    if row is None:
        return None

    encrypted_path = STORAGE_DIR / row["encrypted_name"]

    if not encrypted_path.is_file():
        return None

    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "name": row["original_name"],
        "path": encrypted_path,
        "original_size": row["original_size"],
        "encrypted_size": row["encrypted_size"],
        "created_at": row["created_at"],
    }


def delete_user_file(user_id, file_id):
    """Delete one of the user's files (database row + encrypted file).

    Returns True if a file was deleted, False if this user has no such file.
    Works even if the encrypted file itself is already missing from disk.
    """
    with get_connection() as connection:
        row = connection.execute(
            "SELECT encrypted_name FROM encrypted_files "
            "WHERE id = ? AND user_id = ?",
            (file_id, str(user_id)),
        ).fetchone()

        if row is None:
            return False

        connection.execute(
            "DELETE FROM encrypted_files WHERE id = ? AND user_id = ?",
            (file_id, str(user_id)),
        )

    # Only ever delete inside the encrypted-files folder, using just the name.
    (STORAGE_DIR / Path(row["encrypted_name"]).name).unlink(missing_ok=True)
    return True


init_file_store()
