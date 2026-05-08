import json
import socket
from pathlib import Path

from auth import register_user, authenticate_user
from file_utils import write_file_bytes

HOST = "127.0.0.1"
PORT = 5001
BUFFER_SIZE = 4096
UPLOADS_DIR = Path("uploads")

def recv_json(conn: socket.socket) -> dict:
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Connection closed while receiving JSON.")
        data += chunk
    line, _, _ = data.partition(b"\n")
    return json.loads(line.decode("utf-8"))

def send_json(conn: socket.socket, payload: dict) -> None:
    conn.sendall(json.dumps(payload).encode("utf-8") + b"\n")

def receive_exact_bytes(conn: socket.socket, num_bytes: int) -> bytes:
    data = b""
    while len(data) < num_bytes:
        chunk = conn.recv(min(BUFFER_SIZE, num_bytes - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed while receiving file data.")
        data += chunk
    return data

def handle_client(conn: socket.socket, address) -> None:
    print(f"[+] Connected by {address}")
    try:
        request = recv_json(conn)
        action = request.get("action")
        username = request.get("username", "")
        password = request.get("password", "")

        if action == "register":
            success, message = register_user(username, password)
        elif action == "login":
            success, message = authenticate_user(username, password)
        else:
            send_json(conn, {"status": "error", "message": "Invalid action."})
            return

        send_json(conn, {"status": "ok" if success else "error", "message": message})

        if not success or action != "login":
            return

        file_info = recv_json(conn)
        if file_info.get("action") != "send_file":
            send_json(conn, {"status": "error", "message": "Expected file transfer request."})
            return

        filename = Path(file_info.get("filename", "received_file.bin")).name
        filesize = int(file_info.get("filesize", 0))
        encrypted_data = receive_exact_bytes(conn, filesize)

        UPLOADS_DIR.mkdir(exist_ok=True)
        output_path = UPLOADS_DIR / f"{username}_{filename}"
        write_file_bytes(str(output_path), encrypted_data)

        send_json(conn, {"status": "ok", "message": f"Encrypted file saved as {output_path}"})
        print(f"[+] Received file from {username}: {output_path}")
    except Exception as error:
        print(f"[!] Error handling client {address}: {error}")
        try:
            send_json(conn, {"status": "error", "message": str(error)})
        except Exception:
            pass
    finally:
        conn.close()
        print(f"[-] Connection closed: {address}")

def start_server() -> None:
    print(f"[*] Starting server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print("[*] Server is listening...")
        while True:
            conn, address = server_socket.accept()
            handle_client(conn, address)

if __name__ == "__main__":
    start_server()
    try:
        request = recv_json(conn)
        action = request.get("action")
        username = request.get("username", "")
        password = request.get("password", "")

        if action == "register":
            success, message = register_user(username, password)
        elif action == "login":
            success, message = authenticate_user(username, password)
        else:
            send_json(conn, {"status": "error", "message": "Invalid action."})
            return

        send_json(conn, {"status": "ok" if success else "error", "message": message})

        if not success or action != "login":
            return

        file_info = recv_json(conn)
        if file_info.get("action") != "send_file":
            send_json(conn, {"status": "error", "message": "Expected file transfer request."})
            return

        filename = Path(file_info.get("filename", "received_file.bin")).name
        filesize = int(file_info.get("filesize", 0))
        encrypted_data = receive_exact_bytes(conn, filesize)

        UPLOADS_DIR.mkdir(exist_ok=True)
        output_path = UPLOADS_DIR / f"{username}_{filename}"
        write_file_bytes(str(output_path), encrypted_data)

        send_json(conn, {"status": "ok", "message": f"Encrypted file saved as {output_path}"})
        print(f"[+] Received file from {username}: {output_path}")
    except Exception as error:
        print(f"[!] Error handling client {address}: {error}")
        try:
            send_json(conn, {"status": "error", "message": str(error)})
        except Exception:
            pass
    finally:
        conn.close()
        print(f"[-] Connection closed: {address}")

def start_server() -> None:
    print(f"[*] Starting server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print("[*] Server is listening...")
        while True:
            conn, address = server_socket.accept()
            handle_client(conn, address)

if __name__ == "__main__":
    start_server()
