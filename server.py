"""Concurrent TLS server for authenticated, encrypted file storage."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from auth import LoginRateLimiter, UserStore
from file_utils import list_user_files, sanitize_filename, user_storage_path
from protocol import (
    MAX_FILE_BYTES,
    ProtocolError,
    receive_file,
    receive_json,
    send_file,
    send_json,
    sha256_file,
    validate_file_size,
)


SOCKET_TIMEOUT_SECONDS = 30


def create_tls_context(cert_file: str | Path, key_file: str | Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return context


def create_audit_logger(path: str | Path) -> logging.Logger:
    resolved_path = Path(path).resolve()
    logger = logging.getLogger(f"secure_transfer.audit.{hash(resolved_path)}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.FileHandler(resolved_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def audit(logger: logging.Logger, event: str, **fields: object) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    logger.info(json.dumps(record, separators=(",", ":"), sort_keys=True))


class SecureTransferServer:
    def __init__(
        self,
        host: str,
        port: int,
        cert_file: str | Path,
        key_file: str | Path,
        users_file: str | Path,
        storage_root: str | Path,
        audit_file: str | Path,
        max_workers: int = 20,
    ) -> None:
        self.host = host
        self.port = port
        self.storage_root = Path(storage_root)
        self.users = UserStore(users_file)
        self.rate_limiter = LoginRateLimiter()
        self.audit_logger = create_audit_logger(audit_file)
        self.tls_context = create_tls_context(cert_file, key_file)
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="secure-transfer",
        )
        self._shutdown = threading.Event()
        self.started = threading.Event()
        self.bound_port: int | None = None

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(100)
            server_socket.settimeout(0.5)
            self.bound_port = int(server_socket.getsockname()[1])
            self.started.set()
            print(
                f"Secure Transfer v2 listening on {self.host}:{self.bound_port} "
                "(TLS required)"
            )
            audit(
                self.audit_logger,
                "server_started",
                host=self.host,
                port=self.bound_port,
            )
            try:
                while not self._shutdown.is_set():
                    try:
                        raw_socket, address = server_socket.accept()
                    except socket.timeout:
                        continue
                    self.executor.submit(self._handle_connection, raw_socket, address)
            except KeyboardInterrupt:
                print("\nShutting down securely...")
            finally:
                self._shutdown.set()
                self.executor.shutdown(wait=True, cancel_futures=True)
                audit(self.audit_logger, "server_stopped")

    def shutdown(self) -> None:
        self._shutdown.set()

    def _handle_connection(self, raw_socket: socket.socket, address: tuple) -> None:
        client_ip = str(address[0])
        try:
            with self.tls_context.wrap_socket(raw_socket, server_side=True) as conn:
                conn.settimeout(SOCKET_TIMEOUT_SECONDS)
                audit(
                    self.audit_logger,
                    "tls_connected",
                    client_ip=client_ip,
                    tls_version=conn.version(),
                    cipher=conn.cipher()[0] if conn.cipher() else None,
                )
                self._handle_request(conn, client_ip)
        except (ssl.SSLError, TimeoutError, ConnectionError, OSError) as error:
            audit(
                self.audit_logger,
                "connection_error",
                client_ip=client_ip,
                error_type=type(error).__name__,
            )
        finally:
            try:
                raw_socket.close()
            except OSError:
                pass

    def _handle_request(self, conn: ssl.SSLSocket, client_ip: str) -> None:
        try:
            request = receive_json(conn)
            action = request.get("action")
            username = str(request.get("username", "")).strip()
            password = str(request.get("password", ""))

            if action == "register":
                success, message = self.users.register(username, password)
                send_json(
                    conn,
                    {"status": "ok" if success else "error", "message": message},
                )
                audit(
                    self.audit_logger,
                    "registration_attempt",
                    client_ip=client_ip,
                    username=username,
                    success=success,
                )
                return

            if action != "login":
                raise ProtocolError("Expected register or login action.")

            limiter_key = f"{client_ip}:{username.lower()}"
            allowed, retry_after = self.rate_limiter.is_allowed(limiter_key)
            if not allowed:
                send_json(
                    conn,
                    {
                        "status": "error",
                        "code": "RATE_LIMITED",
                        "message": "Too many failed attempts. Try again later.",
                        "retry_after_seconds": retry_after,
                    },
                )
                audit(
                    self.audit_logger,
                    "login_rate_limited",
                    client_ip=client_ip,
                    username=username,
                    retry_after_seconds=retry_after,
                )
                return

            if not self.users.authenticate(username, password):
                self.rate_limiter.record_failure(limiter_key)
                send_json(
                    conn,
                    {
                        "status": "error",
                        "code": "INVALID_CREDENTIALS",
                        "message": "Invalid username or password.",
                    },
                )
                audit(
                    self.audit_logger,
                    "login_failed",
                    client_ip=client_ip,
                    username=username,
                )
                return

            self.rate_limiter.record_success(limiter_key)
            send_json(conn, {"status": "ok", "message": "Authentication successful."})
            audit(
                self.audit_logger,
                "login_succeeded",
                client_ip=client_ip,
                username=username,
            )
            self._handle_operation(conn, username, client_ip)
        except (ProtocolError, ValueError) as error:
            send_json(conn, {"status": "error", "message": str(error)})
            audit(
                self.audit_logger,
                "request_rejected",
                client_ip=client_ip,
                error_type=type(error).__name__,
            )
        except Exception as error:
            try:
                send_json(conn, {"status": "error", "message": "Request failed."})
            except Exception:
                pass
            audit(
                self.audit_logger,
                "request_error",
                client_ip=client_ip,
                error_type=type(error).__name__,
            )

    def _handle_operation(
        self,
        conn: ssl.SSLSocket,
        username: str,
        client_ip: str,
    ) -> None:
        request = receive_json(conn)
        action = request.get("action")
        if action == "list":
            files = list_user_files(self.storage_root, username)
            send_json(conn, {"status": "ok", "files": files})
            audit(
                self.audit_logger,
                "files_listed",
                client_ip=client_ip,
                username=username,
                count=len(files),
            )
            return

        filename = sanitize_filename(str(request.get("filename", "")))
        storage_path = user_storage_path(self.storage_root, username, filename)

        if action == "upload":
            size = int(request.get("size", 0))
            digest = str(request.get("sha256", ""))
            validate_file_size(size)
            storage_path.parent.mkdir(parents=True, exist_ok=True)
            reservation_path = storage_path.with_suffix(storage_path.suffix + ".lock")
            try:
                with reservation_path.open("x"):
                    pass
            except FileExistsError:
                send_json(
                    conn,
                    {
                        "status": "error",
                        "code": "UPLOAD_IN_PROGRESS",
                        "message": "A transfer for this filename is already in progress.",
                    },
                )
                return
            try:
                if storage_path.exists():
                    send_json(
                        conn,
                        {
                            "status": "error",
                            "code": "FILE_EXISTS",
                            "message": "A file with this name already exists.",
                        },
                    )
                    return
                send_json(conn, {"status": "ready", "max_bytes": MAX_FILE_BYTES})
                actual_digest = receive_file(conn, storage_path, size, digest)
                send_json(
                    conn,
                    {
                        "status": "ok",
                        "message": "Encrypted file stored and verified.",
                        "sha256": actual_digest,
                    },
                )
                audit(
                    self.audit_logger,
                    "file_uploaded",
                    client_ip=client_ip,
                    username=username,
                    filename=filename,
                    encrypted_bytes=size,
                    sha256=actual_digest,
                )
            finally:
                reservation_path.unlink(missing_ok=True)
            return

        if action == "download":
            if not storage_path.is_file():
                send_json(
                    conn,
                    {
                        "status": "error",
                        "code": "NOT_FOUND",
                        "message": "Encrypted file not found.",
                    },
                )
                return
            size = storage_path.stat().st_size
            digest = sha256_file(storage_path)
            send_json(
                conn,
                {
                    "status": "ready",
                    "filename": filename,
                    "size": size,
                    "sha256": digest,
                },
            )
            send_file(conn, storage_path)
            audit(
                self.audit_logger,
                "file_downloaded",
                client_ip=client_ip,
                username=username,
                filename=filename,
                encrypted_bytes=size,
                sha256=digest,
            )
            return

        raise ProtocolError("Unsupported authenticated action.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Secure Transfer v2 TLS server with encrypted-at-rest storage."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5443)
    parser.add_argument("--cert", default="certs/server.crt")
    parser.add_argument("--key", default="certs/server.key")
    parser.add_argument("--users", default="users.json")
    parser.add_argument("--storage", default="uploads")
    parser.add_argument("--audit-log", default="audit.jsonl")
    parser.add_argument("--workers", type=int, default=20)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = SecureTransferServer(
        host=args.host,
        port=args.port,
        cert_file=args.cert,
        key_file=args.key,
        users_file=args.users,
        storage_root=args.storage,
        audit_file=args.audit_log,
        max_workers=args.workers,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
