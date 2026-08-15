import logging
import sys
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

def setup_logging():
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(fmt)
    fh = logging.FileHandler(LOG_DIR / "app.log")
    fh.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(h)
    root.addHandler(fh)
