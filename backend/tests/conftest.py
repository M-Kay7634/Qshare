"""Shared test setup: every test gets its own empty temporary database,
encrypted-file folder and key store, so tests never touch real QShare data."""

import pytest

from app import file_store, key_store, user_store


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    # Point the app at temporary files instead of the real ones.
    monkeypatch.setattr(user_store, "DB_PATH", tmp_path / "test_users.db")
    monkeypatch.setattr(file_store, "DATABASE_PATH", tmp_path / "test_files.db")
    monkeypatch.setattr(file_store, "STORAGE_DIR", tmp_path / "encrypted")
    (tmp_path / "encrypted").mkdir()

    # Create the empty tables in the temporary databases.
    user_store.initialize_database()
    file_store.init_file_store()

    # Start each test with no keys in memory.
    key_store._PRIVATE_KEYS.clear()
    key_store._PUBLIC_KEYS.clear()

    yield
