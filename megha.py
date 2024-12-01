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
