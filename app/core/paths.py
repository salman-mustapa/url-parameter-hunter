"""Containment checks that retain resolved paths and tolerate Windows device prefixes."""
from pathlib import Path


def _ordinary_path(path: Path) -> Path:
    value = str(path)
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\") and len(value) > 6 and value[5:7] == ":\\":
        value = value[4:]
    return Path(value)


def contained_path(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    resolved_root = root.resolve()
    if not _ordinary_path(resolved).is_relative_to(_ordinary_path(resolved_root)):
        raise ValueError("Path is outside the permitted storage directory")
    return resolved
