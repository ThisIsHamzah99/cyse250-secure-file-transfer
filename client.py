"""Command-line client for Secure Transfer v2."""

from __future__ import annotations

import argparse
import getpass
import socket
import ssl
import tempfile
from pathlib import Path

from crypto_utils import FileEncryptionError, decrypt_file, encrypt_file
from file_utils import sanitize_filename
from protocol import (
    ProtocolError,
    receive_file,
    receive_json,
    send_file,
    send_json,
    sha256_file,
    validate_file_size,
)


def create_tls_context(ca_file: str | Path, insecure: bool) -> ssl.SSLContext:
    if insecure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def connect(args: argparse.Namespace) -> ssl.SSLSocket:
    context = create_tls_context(args.ca_file, args.insecure)
    raw_socket = socket.create_connection((args.host, args.port), timeout=args.timeout)
    return context.wrap_socket(raw_socket, server_hostname=args.server_name)


def login(sock: ssl.SSLSocket, username: str) -> None:
    password = getpass.getpass("Account password: ")
    send_json(
        sock,
        {"action": "login", "username": username, "password": password},
    )
    response = receive_json(sock)
    if response.get("status") != "ok":
        raise PermissionError(response.get("message", "Authentication failed."))


def register(args: argparse.Namespace) -> None:
    password = getpass.getpass("Create account password (12+ characters): ")
    confirmation = getpass.getpass("Confirm account password: ")
    if password != confirmation:
        raise ValueError("Passwords do not match.")
    with connect(args) as sock:
        send_json(
            sock,
            {"action": "register", "username": args.username, "password": password},
        )
        response = receive_json(sock)
    print(response.get("message", "No server response."))
    if response.get("status") != "ok":
        raise RuntimeError("Registration was not completed.")


def upload(args: argparse.Namespace) -> None:
    source_path = Path(args.file)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    filename = sanitize_filename(source_path.name)
    passphrase = getpass.getpass("File encryption passphrase (12+ characters): ")
    confirmation = getpass.getpass("Confirm encryption passphrase: ")
    if passphrase != confirmation:
        raise ValueError("Encryption passphrases do not match.")

    with tempfile.TemporaryDirectory(prefix="secure-transfer-") as temporary_directory:
        encrypted_path = Path(temporary_directory) / f"{filename}.sft"
        metadata = encrypt_file(source_path, encrypted_path, passphrase)
        digest = sha256_file(encrypted_path)
        validate_file_size(metadata.encrypted_size)

        with connect(args) as sock:
            login(sock, args.username)
            send_json(
                sock,
                {
                    "action": "upload",
                    "filename": filename,
                    "size": metadata.encrypted_size,
                    "sha256": digest,
                },
            )
            response = receive_json(sock)
            if response.get("status") != "ready":
                raise RuntimeError(response.get("message", "Upload rejected."))
            send_file(sock, encrypted_path)
            final_response = receive_json(sock)
            if final_response.get("status") != "ok":
                raise RuntimeError(final_response.get("message", "Upload failed."))

        print(
            f"Uploaded {filename}: {metadata.plaintext_size} plaintext bytes -> "
            f"{metadata.encrypted_size} authenticated-encrypted bytes."
        )
        print(f"Server verified SHA-256: {final_response['sha256']}")


def list_files(args: argparse.Namespace) -> None:
    with connect(args) as sock:
        login(sock, args.username)
        send_json(sock, {"action": "list"})
        response = receive_json(sock)
    if response.get("status") != "ok":
        raise RuntimeError(response.get("message", "Unable to list files."))
    files = response.get("files", [])
    if not files:
        print("No encrypted files stored for this account.")
        return
    print("Encrypted files:")
    for item in files:
        print(
            f"- {item['filename']} | {item['encrypted_bytes']} bytes | "
            f"{item['modified_utc']}"
        )


def download(args: argparse.Namespace) -> None:
    filename = sanitize_filename(args.filename)
    output_path = Path(args.output or filename)
    if output_path.exists() and not args.overwrite:
        raise FileExistsError(f"Refusing to overwrite {output_path}; use --overwrite.")

    with tempfile.TemporaryDirectory(prefix="secure-transfer-") as temporary_directory:
        encrypted_path = Path(temporary_directory) / f"{filename}.sft"
        with connect(args) as sock:
            login(sock, args.username)
            send_json(sock, {"action": "download", "filename": filename})
            response = receive_json(sock)
            if response.get("status") != "ready":
                raise RuntimeError(response.get("message", "Download rejected."))
            size = int(response["size"])
            digest = str(response["sha256"])
            receive_file(sock, encrypted_path, size, digest)

        passphrase = getpass.getpass("File encryption passphrase: ")
        metadata = decrypt_file(encrypted_path, output_path, passphrase)
        print(
            f"Downloaded, verified, and decrypted {metadata.plaintext_size} bytes "
            f"to {output_path}."
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secure Transfer v2: TLS transport and client-side AES-256-GCM."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5443)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--ca-file", default="certs/ca.crt")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable certificate verification for isolated demos only.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register")
    register_parser.add_argument("username")
    register_parser.set_defaults(handler=register)

    upload_parser = subparsers.add_parser("upload")
    upload_parser.add_argument("username")
    upload_parser.add_argument("file")
    upload_parser.set_defaults(handler=upload)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("username")
    list_parser.set_defaults(handler=list_files)

    download_parser = subparsers.add_parser("download")
    download_parser.add_argument("username")
    download_parser.add_argument("filename")
    download_parser.add_argument("--output")
    download_parser.add_argument("--overwrite", action="store_true")
    download_parser.set_defaults(handler=download)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.insecure:
        print("WARNING: TLS certificate verification is disabled.")
    try:
        args.handler(args)
    except (
        ConnectionError,
        FileEncryptionError,
        OSError,
        PermissionError,
        ProtocolError,
        RuntimeError,
        ValueError,
    ) as error:
        print(f"Error: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
