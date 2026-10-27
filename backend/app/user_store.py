
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "qshare.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)


def create_user(user_id: str, email: str, password_hash: str):
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO users (id, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (user_id, email.strip().lower(), password_hash),
        )


def find_user_by_email(email: str):
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email.strip().lower(),),
        ).fetchone()


def find_user_by_id(user_id: str):
    with get_connection() as connection:
        return connection.execute(
            "SELECT id, email, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


initialize_database()
