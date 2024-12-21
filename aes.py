from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import os

def encrypt_shellcode(file_path):
    # Read the shellcode binary file
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    with open(file_path, "rb") as f:
        shellcode = f.read()
    
    # Generate a random 32-byte key and 16-byte IV for AES encryption
    key = get_random_bytes(32)  # AES-256 requires a 32-byte key
    iv = get_random_bytes(16)   # AES-CBC requires a 16-byte IV
    
    # Encrypt the shellcode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Padding the shellcode to a multiple of AES block size (16 bytes)
    padding_length = 16 - (len(shellcode) % 16)
    padded_shellcode = shellcode + bytes([padding_length] * padding_length)
    encrypted_shellcode = cipher.encrypt(padded_shellcode)
    
    # Write the encrypted shellcode to a new file
    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_shellcode)
    
    print(f"Encrypted shellcode written to: {encrypted_file_path}")
    print(f"Encryption Key (hex): {key.hex()}")
    print(f"Initialization Vector (IV) (hex): {iv.hex()}")

# Specify the path to your shellcode.bin file
file_path = "shellcode.bin"
encrypt_shellcode(file_path)
