import json
import socket
from pathlib import Path

from crypto_utils import encrypt_data, decrypt_data
from file_utils import read_file_bytes, write_file_bytes

HOST = "127.0.0.1"
PORT = 5001
BUFFER_SIZE = 4096

def send_json(sock: socket.socket, payload: dict) -> None:
    sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")

def recv_json(sock: socket.socket) -> dict:
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Server closed the connection.")
        data += chunk
    line, _, _ = data.partition(b"\n")
    return json.loads(line.decode("utf-8"))

def register() -> None:
    username = input("Create username: ").strip()
    password = input("Create password: ").strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        send_json(sock, {"action": "register", "username": username, "password": password})
        response = recv_json(sock)
        print(response.get("message", "No response from server."))

def login_and_send_file() -> None:
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    file_path = input("Enter the path of the file to send: ").strip()
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        print("That file does not exist.")
        return

    file_data = read_file_bytes(file_path)
    encrypted_data = encrypt_data(file_data)

    encrypted_copy = path.with_name(f"encrypted_{path.name}")
    decrypted_copy = path.with_name(f"decrypted_{path.name}")
    write_file_bytes(str(encrypted_copy), encrypted_data)
    write_file_bytes(str(decrypted_copy), decrypt_data(encrypted_data))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        send_json(sock, {"action": "login", "username": username, "password": password})
        response = recv_json(sock)
        if response.get("status") != "ok":
            print(response.get("message", "Login failed."))
            return
        print(response.get("message", "Login successful."))
        send_json(sock, {"action": "send_file", "filename": path.name, "filesize": len(encrypted_data)})
        sock.sendall(encrypted_data)
        final_response = recv_json(sock)
        print(final_response.get("message", "File transfer finished."))
        print(f"Local encrypted copy created: {encrypted_copy}")
        print(f"Local decrypted copy created: {decrypted_copy}")

def main() -> None:
    while True:
        print("\n--- Secure File Transfer System ---")
        print("1. Register")
        print("2. Login and send file")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            register()
        elif choice == "2":
            login_and_send_file()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
