import json
import hashlib
from pathlib import Path

USERS_FILE = Path("users.json")

def _load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        with USERS_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}

def _save_users(users: dict) -> None:
    with USERS_FILE.open("w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def register_user(username: str, password: str) -> tuple[bool, str]:
    username = username.strip()
    if not username or not password:
        return False, "Username and password cannot be empty."
    users = _load_users()
    if username in users:
        return False, "Username already exists."
    users[username] = hash_password(password)
    _save_users(users)
    return True, "Registration successful."

def authenticate_user(username: str, password: str) -> tuple[bool, str]:
    users = _load_users()
    stored_hash = users.get(username)
    if stored_hash is None:
        return False, "Username not found."
    if stored_hash != hash_password(password):
        return False, "Incorrect password."
    return True, "Login successful."
