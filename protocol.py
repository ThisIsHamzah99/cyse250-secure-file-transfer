"""Versioned, length-prefixed protocol and streaming transfer helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
import uuid
from pathlib import Path


PROTOCOL_VERSION = 2
JSON_LENGTH = struct.Struct("!I")
CHUNK_SIZE = 64 * 1024
MAX_JSON_BYTES = 64 * 1024
MAX_FILE_BYTES = 100 * 1024 * 1024


class ProtocolError(Exception):
    """Raised when a peer sends an invalid or incomplete protocol message."""


def receive_exact(sock: socket.socket, size: int) -> bytes:
    if size < 0:
        raise ProtocolError("Negative payload size is invalid.")
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(min(CHUNK_SIZE, size - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed before the payload completed.")
        data.extend(chunk)
    return bytes(data)


def send_json(sock: socket.socket, payload: dict) -> None:
    message = dict(payload)
    message.setdefault("version", PROTOCOL_VERSION)
    encoded = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise ProtocolError("JSON message exceeds the protocol limit.")
    sock.sendall(JSON_LENGTH.pack(len(encoded)) + encoded)


def receive_json(sock: socket.socket) -> dict:
    (size,) = JSON_LENGTH.unpack(receive_exact(sock, JSON_LENGTH.size))
    if not 1 <= size <= MAX_JSON_BYTES:
        raise ProtocolError("Invalid JSON message size.")
    try:
        message = json.loads(receive_exact(sock, size).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("Malformed JSON message.") from error
    if not isinstance(message, dict):
        raise ProtocolError("Protocol messages must be JSON objects.")
    if message.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("Unsupported protocol version.")
    return message


def validate_file_size(size: int) -> None:
    if not 1 <= size <= MAX_FILE_BYTES:
        raise ProtocolError(
            f"File size must be between 1 byte and {MAX_FILE_BYTES} bytes."
        )


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def send_file(sock: socket.socket, path: str | Path) -> None:
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            sock.sendall(chunk)


def receive_file(
    sock: socket.socket,
    destination: str | Path,
    expected_size: int,
    expected_sha256: str,
) -> str:
    validate_file_size(expected_size)
    if len(expected_sha256) != 64:
        raise ProtocolError("Invalid SHA-256 digest.")

    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = destination_path.with_name(
        f".{destination_path.name}.{uuid.uuid4().hex}.part"
    )
    digest = hashlib.sha256()
    remaining = expected_size
    try:
        with temporary_path.open("wb") as file:
            while remaining:
                chunk = sock.recv(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ConnectionError("Connection closed during file transfer.")
                file.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            file.flush()
            os.fsync(file.fileno())

        actual_digest = digest.hexdigest()
        if not hmac.compare_digest(actual_digest, expected_sha256.lower()):
            raise ProtocolError("Transfer integrity verification failed.")
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, destination_path)
        return actual_digest
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

