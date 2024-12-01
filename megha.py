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



    
