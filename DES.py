import os
from Crypto.Cipher import DES
import base64

# Set input and output directories
INPUT_PATH = os.path.join(os.path.expanduser('~/Koleya/5th Term/Introduction to Cryptography/Coursework Project'), 'CourseWork', 'input')
OUTPUT_PATH = os.path.join(os.path.expanduser('~/Koleya/5th Term/Introduction to Cryptography/Coursework Project'), 'CourseWork', 'output')

# Create directories if they don't exist
os.makedirs(INPUT_PATH, exist_ok=True)
os.makedirs(OUTPUT_PATH, exist_ok=True)

def pad_text(text):
    # Add padding to make text a multiple of 8 bytes
    padding_length = 8 - (len(text) % 8)
    return text + bytes([padding_length] * padding_length)

def remove_padding(text):
    # Remove padding from decrypted text
    padding_length = text[-1]
    return text[:-padding_length]

# Encrypt a file using DES
def encrypt_file(input_filename, output_filename):
    # Generate random key and IV
    key = os.urandom(8)
    iv = os.urandom(8)
    
    # Read input file
    input_file = os.path.join(INPUT_PATH, input_filename)
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Encrypt data
    cipher = DES.new(key, DES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad_text(data))
    
    # Save encrypted file
    output_file = os.path.join(OUTPUT_PATH, output_filename)
    with open(output_file, 'wb') as f:
        f.write(iv)
        f.write(encrypted_data)
    
    return key  # Return key for decryption

def decrypt_file(input_filename, output_filename, key):
    # Decrypt a file using DES
    # Read encrypted file
    input_file = os.path.join(OUTPUT_PATH, input_filename)
    with open(input_file, 'rb') as f:
        iv = f.read(8)  # First 8 bytes are IV
        encrypted_data = f.read()
    
    # Decrypt data
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = remove_padding(cipher.decrypt(encrypted_data))
    
    # Save decrypted file
    output_file = os.path.join(OUTPUT_PATH, output_filename)
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

if __name__ == "__main__":
    # Create a test file
    test_content = b"Hello, this is a test message!"
    with open(os.path.join(INPUT_PATH, 'original.txt'), 'wb') as f:
        f.write(test_content)
    
    print(f"Input directory: {INPUT_PATH}")
    print(f"Output directory: {OUTPUT_PATH}")
    
    # Encrypt and decrypt
    key = encrypt_file('original.txt', 'encrypted.bin')
    decrypt_file('encrypted.bin', 'decrypted.txt', key)
    
    print("\nFiles created:")
    print(f"Original: {os.path.join(INPUT_PATH, 'original.txt')}")
    print(f"Encrypted: {os.path.join(OUTPUT_PATH, 'encrypted.bin')}")
    print(f"Decrypted: {os.path.join(OUTPUT_PATH, 'decrypted.txt')}")