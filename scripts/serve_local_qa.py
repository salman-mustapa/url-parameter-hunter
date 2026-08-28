"""Disposable, loopback-only application server for manual UI verification.

Run: python -m scripts.serve_local_qa --port 19001
The account qa_operator / Local-QA-Only-2026! is synthetic, not a deployment default.
"""

import argparse
import os
import secrets
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=19001)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="hunter-qa-") as directory:
        os.environ.update({
            "APP_ENV": "test", "JWT_SECRET": secrets.token_urlsafe(48),
            "DATABASE_URL": f"sqlite+aiosqlite:///{Path(directory) / 'qa.db'}",
            "STORAGE_DIR": str(Path(directory) / "storage"),
            "REDIS_URL": "redis://127.0.0.1:1/0", "LLM_ENABLED": "false",
            "COOKIE_SECURE": "false", "CORS_ORIGINS": "",
            "AUTO_RESUME_SCANS_ON_STARTUP": "false", "SEED_DEFAULT_USERS": "true",
            "BOOTSTRAP_ADMIN_USERNAME": "qa_operator",
            "BOOTSTRAP_ADMIN_EMAIL": "qa@example.invalid",
            "BOOTSTRAP_ADMIN_PASSWORD": "Local-QA-Only-2026!",
            "BOOTSTRAP_USER_USERNAME": "", "BOOTSTRAP_USER_PASSWORD": "",
        })
        import uvicorn
        uvicorn.run("app.main:app", host="127.0.0.1", port=args.port, access_log=False)


if __name__ == "__main__":
    main()
