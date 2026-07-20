"""Streaming AES-256-GCM file encryption for client-side confidentiality."""

from __future__ import annotations

import json
import os
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"SFT2"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER = struct.Struct("!4s16s12sI")
CHUNK_SIZE = 64 * 1024
MAX_AAD_SIZE = 4096


@dataclass(frozen=True)
class EncryptionMetadata:
    original_name: str
    plaintext_size: int
    encrypted_size: int


class FileEncryptionError(Exception):
    """Raised when an encrypted envelope is malformed or fails authentication."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Encryption passphrase must contain at least 12 characters.")
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )


def encrypt_file(
    source: str | Path,
    destination: str | Path,
    passphrase: str,
) -> EncryptionMetadata:
    source_path = Path(source)
    destination_path = Path(destination)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    associated_data = json.dumps(
        {"format": 2, "filename": source_path.name},
        separators=(",", ":"),
    ).encode("utf-8")
    key = _derive_key(passphrase, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(associated_data)

    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = destination_path.with_name(
        f".{destination_path.name}.{uuid.uuid4().hex}.part"
    )
    plaintext_size = 0
    try:
        with source_path.open("rb") as source_file, temporary_path.open("wb") as output:
            output.write(HEADER.pack(MAGIC, salt, nonce, len(associated_data)))
            output.write(associated_data)
            for chunk in iter(lambda: source_file.read(CHUNK_SIZE), b""):
                plaintext_size += len(chunk)
                output.write(encryptor.update(chunk))
            output.write(encryptor.finalize())
            output.write(encryptor.tag)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, destination_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

    return EncryptionMetadata(
        original_name=source_path.name,
        plaintext_size=plaintext_size,
        encrypted_size=destination_path.stat().st_size,
    )


def decrypt_file(
    source: str | Path,
    destination: str | Path,
    passphrase: str,
) -> EncryptionMetadata:
    source_path = Path(source)
    destination_path = Path(destination)
    total_size = source_path.stat().st_size
    minimum_size = HEADER.size + TAG_SIZE
    if total_size <= minimum_size:
        raise FileEncryptionError("Encrypted file is too short.")

    with source_path.open("rb") as source_file:
        header_bytes = source_file.read(HEADER.size)
        if len(header_bytes) != HEADER.size:
            raise FileEncryptionError("Encrypted file header is incomplete.")
        magic, salt, nonce, aad_size = HEADER.unpack(header_bytes)
        if magic != MAGIC or not 1 <= aad_size <= MAX_AAD_SIZE:
            raise FileEncryptionError("Unsupported or malformed encrypted file.")
        associated_data = source_file.read(aad_size)
        if len(associated_data) != aad_size:
            raise FileEncryptionError("Encrypted metadata is incomplete.")
        try:
            metadata = json.loads(associated_data.decode("utf-8"))
            original_name = str(metadata["filename"])
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as error:
            raise FileEncryptionError("Encrypted metadata is invalid.") from error

        ciphertext_start = HEADER.size + aad_size
        ciphertext_size = total_size - ciphertext_start - TAG_SIZE
        if ciphertext_size < 0:
            raise FileEncryptionError("Encrypted payload length is invalid.")
        source_file.seek(total_size - TAG_SIZE)
        tag = source_file.read(TAG_SIZE)
        source_file.seek(ciphertext_start)

        key = _derive_key(passphrase, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(associated_data)

        destination_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = destination_path.with_name(
            f".{destination_path.name}.{uuid.uuid4().hex}.part"
        )
        remaining = ciphertext_size
        plaintext_size = 0
        try:
            with temporary_path.open("wb") as output:
                while remaining:
                    chunk = source_file.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise FileEncryptionError("Encrypted payload is incomplete.")
                    remaining -= len(chunk)
                    plaintext = decryptor.update(chunk)
                    plaintext_size += len(plaintext)
                    output.write(plaintext)
                final_plaintext = decryptor.finalize()
                plaintext_size += len(final_plaintext)
                output.write(final_plaintext)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, destination_path)
        except InvalidTag as error:
            temporary_path.unlink(missing_ok=True)
            raise FileEncryptionError(
                "Authentication failed: wrong passphrase or modified ciphertext."
            ) from error
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

    return EncryptionMetadata(
        original_name=original_name,
        plaintext_size=plaintext_size,
        encrypted_size=total_size,
    )
