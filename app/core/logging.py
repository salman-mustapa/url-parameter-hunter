import logging
import os

LOG_DIR = os.environ.get("LOG_DIR", "")
LOG_FILE = os.path.join(LOG_DIR, "app.log") if LOG_DIR else None

_configured = False


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
    _configured = True