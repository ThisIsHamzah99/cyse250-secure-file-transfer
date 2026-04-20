# Secure File Transfer System

This project was created for CYSE 250. It is a Python socket programming project that allows a user to register, log in, and send an encrypted file to a server.

## Requirements Covered
- Socket programming
- Files
- Encryption and decryption
- Authentication
- Loops
- Functions
- Lists and dictionaries (JSON/dictionary-based user storage)

## Files
- `server.py`
- `client.py`
- `auth.py`
- `crypto_utils.py`
- `file_utils.py`
- `users.json`
- `uploads/`

## How to Run

Open two terminals in the project folder.

### Terminal 1
```bash
python3 server.py
```

### Terminal 2
```bash
python3 client.py
```

## Demo
1. Start the server
2. Run the client
3. Register
4. Login and send `sample.txt`
5. Show the uploaded encrypted file in `uploads/`
