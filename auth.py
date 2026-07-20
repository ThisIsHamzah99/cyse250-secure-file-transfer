"""Authentication storage and brute-force protection.

Passwords are stored with scrypt, a unique random salt, and explicit work-factor
parameters. The module also understands the prototype's legacy SHA-256 records
and upgrades them after a successful login.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from pathlib import Path


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 12
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LENGTH = 32


class UserStore:
    """Thread-safe JSON-backed user store for the learning server."""

    def __init__(self, path: str | Path = "users.json") -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def register(self, username: str, password: str) -> tuple[bool, str]:
        username = username.strip()
        validation_error = validate_credentials(username, password)
        if validation_error:
            return False, validation_error

        with self._lock:
            users = self._load()
            if username in users:
                return False, "Username already exists."
            users[username] = create_password_record(password)
            self._save(users)
        return True, "Registration successful."

    def authenticate(self, username: str, password: str) -> bool:
        with self._lock:
            users = self._load()
            record = users.get(username)
            if record is None:
                verify_password(password, create_password_record("timing-only-value"))
                return False

            if isinstance(record, str):
                legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
                if not hmac.compare_digest(record, legacy_hash):
                    return False
                users[username] = create_password_record(password)
                self._save(users)
                return True

            return verify_password(password, record)

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            with self.path.open("r", encoding="utf-8") as file:
                data = json.load(file)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, users: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary_path.open("w", encoding="utf-8") as file:
            json.dump(users, file, indent=2, sort_keys=True)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, self.path)


class LoginRateLimiter:
    """In-memory sliding-window limiter with a temporary account/IP lockout."""

    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 60,
        lockout_seconds: int = 300,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str, now: float | None = None) -> tuple[bool, int]:
        current_time = time.monotonic() if now is None else now
        with self._lock:
            locked_until = self._locked_until.get(key, 0)
            if locked_until > current_time:
                return False, max(1, int(locked_until - current_time))
            self._locked_until.pop(key, None)
            self._prune(key, current_time)
            return True, 0

    def record_failure(self, key: str, now: float | None = None) -> None:
        current_time = time.monotonic() if now is None else now
        with self._lock:
            self._prune(key, current_time)
            failures = self._failures[key]
            failures.append(current_time)
            if len(failures) >= self.max_failures:
                self._locked_until[key] = current_time + self.lockout_seconds
                failures.clear()

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def _prune(self, key: str, now: float) -> None:
        failures = self._failures[key]
        cutoff = now - self.window_seconds
        while failures and failures[0] < cutoff:
            failures.popleft()
        if not failures:
            self._failures.pop(key, None)


def validate_credentials(username: str, password: str) -> str | None:
    if not USERNAME_PATTERN.fullmatch(username):
        return "Username must be 3-32 characters using letters, numbers, ., _, or -."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must contain at least {MIN_PASSWORD_LENGTH} characters."
    return None


def create_password_record(password: str) -> dict:
    salt = os.urandom(16)
    derived_key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_KEY_LENGTH,
    )
    return {
        "scheme": "scrypt",
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(derived_key).decode("ascii"),
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "dklen": SCRYPT_KEY_LENGTH,
    }


def verify_password(password: str, record: dict) -> bool:
    try:
        if record.get("scheme") != "scrypt":
            return False
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["hash"], validate=True)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(record["n"]),
            r=int(record["r"]),
            p=int(record["p"]),
            dklen=int(record["dklen"]),
        )
    except (KeyError, TypeError, ValueError):
        return False
    return hmac.compare_digest(candidate, expected)
