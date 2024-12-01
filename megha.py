from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate a secure random encryption key
def generate_key():
    return get_random_bytes(16)  # 128-bit key

# Encrypt a message using AES
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + ciphertext).decode()  # Combine nonce and ciphertext

# Decrypt an AES encrypted message
def decrypt_message(key, encrypted_message):
    raw_data = base64.b64decode(encrypted_message)
    nonce = raw_data[:16]  # Extract nonce
    ciphertext = raw_data[16:]  # Extract ciphertext
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()


if __name__ == "__main__":
    # Step 1: Generate a secure key
    secret_key = generate_key()
    print(f"Generated Key: {base64.b64encode(secret_key).decode()}")  # Display the key in a readable format

    # Step 2: Encrypt a message
    message = "Sensitive data needs protection!"
    encrypted = encrypt_message(secret_key, message)
    print(f"Encrypted Message: {encrypted}")

    # Step 3: Decrypt the message
    decrypted = decrypt_message(secret_key, encrypted)
    print(f"Decrypted Message: {decrypted}")



import hashlib
import getpass


USER_DB = {}

# Hash a password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Register a new user
def register_user(username, password):
    if username in USER_DB:
        print("Username already exists. Please choose a different username.")
        return False
    USER_DB[username] = hash_password(password)
    print("User registered successfully!")
    return True

# Authenticate an existing user
def authenticate_user(username, password):
    if username not in USER_DB:
        print("Authentication failed: User does not exist.")
        return False
    if USER_DB[username] == hash_password(password):
        print("Authentication successful! Welcome!")
        return True
    else:
        print("Authentication failed: Incorrect password.")
        return False

# Main application
if __name__ == "__main__":
    print("Welcome to the User Authentication System!")
    while True:
        print("\nOptions:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            username = input("Enter a username: ")
            password = getpass.getpass("Enter a password: ")  # Use getpass to hide input
            register_user(username, password)

        elif choice == "2":
            username = input("Enter your username: ")
            password = getpass.getpass("Enter your password: ")
            authenticate_user(username, password)

        elif choice == "3":
            print("Exiting the system. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")
