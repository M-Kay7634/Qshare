"""Shared test setup: every test gets its own empty temporary databases,
encrypted-file folder and key store, so tests never touch real QShare data
and never use your real master key. Rate-limit counters also start empty."""

import base64
import os

# A fixed TEST master key, set BEFORE the app is imported. Your real
# .env master key is never used by the tests.
TEST_MASTER_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
os.environ["QSHARE_MASTER_KEY"] = TEST_MASTER_KEY

import pytest  # noqa: E402

from app import file_store, key_store, limits, user_store  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    # Point the app at temporary files instead of the real ones.
    monkeypatch.setattr(user_store, "DB_PATH", tmp_path / "test_users.db")
    monkeypatch.setattr(file_store, "DATABASE_PATH", tmp_path / "test_files.db")
    monkeypatch.setattr(file_store, "STORAGE_DIR", tmp_path / "encrypted")
    monkeypatch.setattr(key_store, "DATABASE_PATH", tmp_path / "test_keys.db")
    (tmp_path / "encrypted").mkdir()

    # Create the empty tables in the temporary databases.
    user_store.initialize_database()
    file_store.init_file_store()
    # (key_store creates its own table automatically when first used)

    limits.reset_all()  # every test starts with fresh rate-limit counters
    yield
    limits.reset_all()