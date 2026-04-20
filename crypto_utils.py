def encrypt_data(data: bytes, key: int = 7) -> bytes:
    return bytes(byte ^ key for byte in data)

def decrypt_data(data: bytes, key: int = 7) -> bytes:
    return bytes(byte ^ key for byte in data)
