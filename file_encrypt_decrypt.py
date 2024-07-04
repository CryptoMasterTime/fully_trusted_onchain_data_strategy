from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import os

def generate_secret_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_file(file_path, password):
    secret_key = generate_secret_key(password)
    cipher = AES.new(secret_key, AES.MODE_CBC)
    iv = cipher.iv
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    encrypted_file_data = iv + encrypted_data
    
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_file_data)
    
    print(f"File encrypted and saved as: {encrypted_file_path}")

def decrypt_file(encrypted_file_path, password):
    secret_key = generate_secret_key(password)
    
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_file_data = encrypted_file.read()
    
    iv = encrypted_file_data[:AES.block_size]
    encrypted_data = encrypted_file_data[AES.block_size:]
    
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    original_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(original_file_path, 'wb') as original_file:
        original_file.write(decrypted_data)
    
    print(f"File decrypted and saved as: {original_file_path}")

if __name__ == "__main__":

    password = "**********"
    
    # Encrypt
    file_to_encrypt = "trading_strategy.txt"
    encrypt_file(file_to_encrypt, password)
    
    #Decrypt
    file_to_decrypt = "trading_strategy.txt.enc"
    decrypt_file(file_to_decrypt, password)
