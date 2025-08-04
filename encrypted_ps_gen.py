import secrets
import string
import json
from cryptography.fernet import Fernet
from pathlib import Path

DATA_FILE = Path("encrypted_passwords.json")

# === Core Functions ===

def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def generate_key():
    return Fernet.generate_key()

def encrypt_password(password, key):
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    save_encrypted_password(encrypted.decode(), key.decode())
    return encrypted

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

def save_encrypted_password(encrypted, key):
    entry = {"key": key, "encrypted_password": encrypted}
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = []
    else:
        data = []
    data.append(entry)
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def list_saved_passwords():
    if not DATA_FILE.exists():
        return []
    with open(DATA_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

# === Example Usage ===

if __name__ == "__main__":
    # Generate password
    password = generate_password()
    print(f"Generated Password: {password}")

    # Generate encryption key
    key = generate_key()
    print(f"Encryption Key: {key.decode()}")

    # Encrypt and save password
    encrypted = encrypt_password(password, key)
    print(f"Encrypted Password: {encrypted.decode()}")

    # List saved entries
    print("\nSaved Entries:")
    for entry in list_saved_passwords():
        print(entry)

    # Optional: Decrypt latest
    print("\nDecryption Test:")
    try:
        decrypted = decrypt_password(entry["encrypted_password"], entry["key"])
        print(f"Decrypted Password: {decrypted}")
    except Exception as e:
        print(f"Failed to decrypt: {e}")
