import json
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from auth import LoginRateLimiter, UserStore
from crypto_utils import FileEncryptionError, decrypt_file, encrypt_file
from file_utils import sanitize_filename, user_storage_path
from generate_certs import generate_certificates
from protocol import (
    ProtocolError,
    receive_file,
    receive_json,
    send_file,
    send_json,
    sha256_file,
)
from server import SecureTransferServer


class UserStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.users_path = Path(self.temporary_directory.name) / "users.json"
        self.store = UserStore(self.users_path)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_registration_uses_unique_scrypt_record(self) -> None:
        success, _ = self.store.register("analyst", "correct horse battery staple")
        self.assertTrue(success)
        record = json.loads(self.users_path.read_text(encoding="utf-8"))["analyst"]
        self.assertEqual(record["scheme"], "scrypt")
        self.assertNotIn("correct horse battery staple", json.dumps(record))
        self.assertEqual(len(record["salt"]), 24)

    def test_authentication_accepts_correct_password_only(self) -> None:
        self.store.register("analyst", "correct horse battery staple")
        self.assertTrue(
            self.store.authenticate("analyst", "correct horse battery staple")
        )
        self.assertFalse(self.store.authenticate("analyst", "wrong-password-value"))
        self.assertFalse(
            self.store.authenticate("missing", "correct horse battery staple")
        )

    def test_rejects_weak_credentials(self) -> None:
        success, _ = self.store.register("x", "short")
        self.assertFalse(success)
        self.assertFalse(self.users_path.exists())


class LoginRateLimiterTests(unittest.TestCase):
    def test_locks_after_threshold_and_recovers(self) -> None:
        limiter = LoginRateLimiter(
            max_failures=3,
            window_seconds=60,
            lockout_seconds=120,
        )
        for timestamp in (0.0, 1.0, 2.0):
            limiter.record_failure("127.0.0.1:analyst", now=timestamp)
        allowed, retry_after = limiter.is_allowed("127.0.0.1:analyst", now=3.0)
        self.assertFalse(allowed)
        self.assertEqual(retry_after, 119)
        allowed, _ = limiter.is_allowed("127.0.0.1:analyst", now=123.0)
        self.assertTrue(allowed)


class FileEncryptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_streaming_round_trip_preserves_binary_data(self) -> None:
        plaintext = self.root / "evidence.bin"
        encrypted = self.root / "evidence.bin.sft"
        recovered = self.root / "recovered.bin"
        original_data = bytes(range(256)) * 2048
        plaintext.write_bytes(original_data)
        encryption = encrypt_file(
            plaintext,
            encrypted,
            "long and unique file passphrase",
        )
        decryption = decrypt_file(
            encrypted,
            recovered,
            "long and unique file passphrase",
        )
        self.assertEqual(recovered.read_bytes(), original_data)
        self.assertEqual(encryption.plaintext_size, len(original_data))
        self.assertEqual(decryption.original_name, "evidence.bin")
        self.assertNotIn(original_data[:64], encrypted.read_bytes())

    def test_ciphertext_tampering_is_detected(self) -> None:
        plaintext = self.root / "evidence.txt"
        encrypted = self.root / "evidence.txt.sft"
        recovered = self.root / "recovered.txt"
        plaintext.write_text("security evidence" * 100, encoding="utf-8")
        encrypt_file(plaintext, encrypted, "long and unique file passphrase")
        tampered = bytearray(encrypted.read_bytes())
        tampered[-20] ^= 0x01
        encrypted.write_bytes(tampered)
        with self.assertRaises(FileEncryptionError):
            decrypt_file(encrypted, recovered, "long and unique file passphrase")
        self.assertFalse(recovered.exists())

    def test_wrong_passphrase_is_rejected(self) -> None:
        plaintext = self.root / "evidence.txt"
        encrypted = self.root / "evidence.txt.sft"
        plaintext.write_text("sensitive lab result", encoding="utf-8")
        encrypt_file(plaintext, encrypted, "long and unique file passphrase")
        with self.assertRaises(FileEncryptionError):
            decrypt_file(encrypted, self.root / "out.txt", "different long passphrase")


class ProtocolTests(unittest.TestCase):
    def test_length_prefixed_json_round_trip(self) -> None:
        left, right = socket.socketpair()
        try:
            send_json(left, {"action": "list", "request_id": "abc-123"})
            received = receive_json(right)
            self.assertEqual(received["action"], "list")
            self.assertEqual(received["request_id"], "abc-123")
            self.assertEqual(received["version"], 2)
        finally:
            left.close()
            right.close()

    def test_receive_file_rejects_wrong_digest(self) -> None:
        left, right = socket.socketpair()
        data = b"encrypted-payload" * 100
        sender = threading.Thread(target=lambda: (left.sendall(data), left.close()))
        sender.start()
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "payload.sft"
            with self.assertRaises(ProtocolError):
                receive_file(right, destination, len(data), "0" * 64)
            self.assertFalse(destination.exists())
        sender.join()
        right.close()

    def test_filename_validation_blocks_traversal(self) -> None:
        with self.assertRaises(ValueError):
            sanitize_filename("../../users.json")
        path = user_storage_path("uploads", "analyst", "evidence.txt")
        self.assertEqual(path, Path("uploads/analyst/evidence.txt.sft"))


class EndToEndTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary_directory.name)
        cls.certs = cls.root / "certs"
        generate_certificates(cls.certs)
        cls.server = SecureTransferServer(
            host="127.0.0.1",
            port=0,
            cert_file=cls.certs / "server.crt",
            key_file=cls.certs / "server.key",
            users_file=cls.root / "users.json",
            storage_root=cls.root / "uploads",
            audit_file=cls.root / "audit.jsonl",
            max_workers=4,
        )
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True,
        )
        cls.server_thread.start()
        if not cls.server.started.wait(timeout=10):
            raise RuntimeError("Test server did not start.")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server_thread.join(timeout=5)
        cls.temporary_directory.cleanup()

    def connect(self) -> ssl.SSLSocket:
        context = ssl.create_default_context(cafile=str(self.certs / "ca.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection(
            ("127.0.0.1", self.server.bound_port),
            timeout=5,
        )
        return context.wrap_socket(raw, server_hostname="localhost")

    def login(self, sock: ssl.SSLSocket) -> None:
        send_json(
            sock,
            {
                "action": "login",
                "username": "analyst",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(receive_json(sock)["status"], "ok")

    def test_register_upload_list_download_and_decrypt(self) -> None:
        with self.connect() as sock:
            send_json(
                sock,
                {
                    "action": "register",
                    "username": "analyst",
                    "password": "correct horse battery staple",
                },
            )
            self.assertEqual(receive_json(sock)["status"], "ok")

        original = self.root / "evidence.txt"
        encrypted = self.root / "evidence.txt.sft"
        downloaded = self.root / "downloaded.sft"
        recovered = self.root / "recovered.txt"
        original.write_text("verified security evidence\n" * 5000, encoding="utf-8")
        metadata = encrypt_file(
            original,
            encrypted,
            "long and unique file passphrase",
        )
        digest = sha256_file(encrypted)

        with self.connect() as sock:
            self.login(sock)
            send_json(
                sock,
                {
                    "action": "upload",
                    "filename": "evidence.txt",
                    "size": metadata.encrypted_size,
                    "sha256": digest,
                },
            )
            self.assertEqual(receive_json(sock)["status"], "ready")
            send_file(sock, encrypted)
            upload_response = receive_json(sock)
            self.assertEqual(upload_response["status"], "ok")
            self.assertEqual(upload_response["sha256"], digest)

        with self.connect() as sock:
            self.login(sock)
            send_json(sock, {"action": "list"})
            listing = receive_json(sock)
            self.assertEqual(listing["files"][0]["filename"], "evidence.txt")

        with self.connect() as sock:
            self.login(sock)
            send_json(sock, {"action": "download", "filename": "evidence.txt"})
            response = receive_json(sock)
            self.assertEqual(response["status"], "ready")
            receive_file(
                sock,
                downloaded,
                int(response["size"]),
                response["sha256"],
            )

        decrypt_file(downloaded, recovered, "long and unique file passphrase")
        self.assertEqual(recovered.read_bytes(), original.read_bytes())
        audit_log = (self.root / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn('"event":"file_uploaded"', audit_log)
        self.assertIn('"event":"file_downloaded"', audit_log)


if __name__ == "__main__":
    unittest.main()
