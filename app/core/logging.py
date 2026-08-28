import logging
import os

from app.reporting.redaction import RedactionEngine

LOG_DIR = os.environ.get("LOG_DIR", "")
LOG_FILE = os.path.join(LOG_DIR, "app.log") if LOG_DIR else None

_configured = False


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        # Includes formatted exception text, not only the original log message.
        return RedactionEngine.redact_text(super().format(record))


def setup_logging(level: int = logging.INFO) -> None:
    global _configured
    if _configured:
        return
    handlers = [logging.StreamHandler()]
    if LOG_FILE:
        os.makedirs(LOG_DIR, exist_ok=True)
        handlers.append(logging.FileHandler(LOG_FILE))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=handlers,
    )
    for handler in logging.getLogger().handlers:
        handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    _configured = True
