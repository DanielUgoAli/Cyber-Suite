import random
import string
from cryptography.fernet import Fernet

# Step 1: Generate a random strong password
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Step 2: Generate an encryption key
def generate_key():
    key = Fernet.generate_key()
    return key

# Step 3: Encrypt the password
def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode())
    return encrypted

# Step 4: Decrypt the password
def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_password).decode()
    return decrypted

# # Step 5: Run the process
# if __name__ == "__main__":
#     # Generate password
#     password = generate_password()
#     print(f"Generated Password: {password}")

#     # Generate encryption key
#     key = generate_key()
#     print(f"Encryption Key (save this safely!): {key.decode()}")

#     # Encrypt the password
#     encrypted_password = encrypt_password(password, key)
#     print(f"Encrypted Password: {encrypted_password.decode()}")

#     # Decrypt to verify
#     decrypted_password = decrypt_password(encrypted_password, key)
#     print(f"Decrypted Password (for verification): {decrypted_password}")
