from pathlib import Path

def read_file_bytes(file_path: str) -> bytes:
    path = Path(file_path)
    with path.open("rb") as file:
        return file.read()

def write_file_bytes(file_path: str, data: bytes) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as file:
        file.write(data)
