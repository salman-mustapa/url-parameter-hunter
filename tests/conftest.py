"""Run tests against a disposable database, never the operator's saved scans."""
import asyncio
import os
import tempfile
from pathlib import Path

import pytest

_test_directory = tempfile.TemporaryDirectory(prefix="hunter-tests-")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{Path(_test_directory.name) / 'tests.db'}"
os.environ["STORAGE_DIR"] = str(Path(_test_directory.name) / "storage")
os.environ["REDIS_URL"] = "redis://127.0.0.1:1/0"
os.environ["JWT_SECRET"] = "test-only-secret-not-used-by-the-application-123456789"
os.environ["APP_ENV"] = "test"
os.environ["LLM_ENABLED"] = "false"
os.environ["SEED_DEFAULT_USERS"] = "false"
os.environ["AUTO_RESUME_SCANS_ON_STARTUP"] = "false"


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def isolated_database():
    from app.core.db import engine, init_db

    async def create():
        await init_db()
    asyncio.run(create())
    yield
    asyncio.run(engine.dispose())
    _test_directory.cleanup()
