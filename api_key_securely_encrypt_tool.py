from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

def generate_secret_key_from_password(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_api_key(api_key, secret_key):
    cipher = AES.new(secret_key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(api_key.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_api_key(encrypted_str, secret_key):
    encrypted_data = base64.b64decode(encrypted_str)
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

if __name__ == "__main__":
    api_key = "secret-api-key"
    password = "cmtqpax9009"
    secret_key = generate_secret_key_from_password(password)
    encrypted_str = encrypt_api_key(api_key, secret_key)
    print(f"Encrypted String: {encrypted_str}")
    decrypted_api_key = decrypt_api_key(encrypted_str, secret_key)
    print(f"Decrypted API Key: {decrypted_api_key}")
