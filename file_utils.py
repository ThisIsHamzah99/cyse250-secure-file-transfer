"""Safe storage-path and listing helpers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path


SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")


def sanitize_filename(filename: str) -> str:
    candidate = filename.strip()
    if Path(candidate).name != candidate or candidate in {".", ".."}:
        raise ValueError("File paths and traversal components are not allowed.")
    if not SAFE_FILENAME.fullmatch(candidate):
        raise ValueError(
            "Filename must be 1-128 characters using letters, numbers, spaces, ., _, or -."
        )
    return candidate


def user_storage_path(root: str | Path, username: str, filename: str) -> Path:
    safe_filename = sanitize_filename(filename)
    return Path(root) / username / f"{safe_filename}.sft"


def list_user_files(root: str | Path, username: str) -> list[dict]:
    user_directory = Path(root) / username
    if not user_directory.exists():
        return []
    files = []
    for path in sorted(user_directory.glob("*.sft")):
        stat = path.stat()
        files.append(
            {
                "filename": path.name.removesuffix(".sft"),
                "encrypted_bytes": stat.st_size,
                "modified_utc": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc
                ).isoformat(),
            }
        )
    return files
