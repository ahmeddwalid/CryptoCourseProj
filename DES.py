import os
from Crypto.Cipher import DES
import base64

# Set input and output directories
# The "os.path.join" automatically inserts the correct path separator 3shan el code ykoon platform-independent
# "os.path.expanduser" expands the '~' to the current user's home directory instead of searching for a directory named '~'
INPUT_PATH = os.path.join(os.path.expanduser('~/Koleya/5th Term/Introduction to Cryptography/Coursework Project'), 'CourseWork', 'input')
OUTPUT_PATH = os.path.join(os.path.expanduser('~/Koleya/5th Term/Introduction to Cryptography/Coursework Project'), 'CourseWork', 'output')

# Create directories if they don't exist and "exist_ok=True" prevents errors if the directory already exists
os.makedirs(INPUT_PATH, exist_ok=True)
os.makedirs(OUTPUT_PATH, exist_ok=True)

# Add padding to make text a multiple of 8 bytes as the DES requires the input data size to be a multiple of its block size (which is 8 bytes)
def pad_text(text):
    padding_length = 8 - (len(text) % 8)  # Calculate the number of padding bytes needed
    return text + bytes([padding_length] * padding_length)  # Add padding bytes

# Remove padding from decrypted text
def remove_padding(text):
    # The last byte of the text indicates the number of padding bytes added during encryption
    padding_length = text[-1]  # Extract the padding length
    return text[:-padding_length]  # Remove the padding bytes from the end

# Encrypt a file using DES
def encrypt_file(input_filename, output_filename):
    key = os.urandom(8)  # Generate a random key of size 8 Bytes
    iv = os.urandom(8)  # Generate a random initialization vector (IV) of size 8 Bytes
    
    # Construct the input file path and read its contents as binary data
    input_file = os.path.join(INPUT_PATH, input_filename)
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Create a DES cipher object in CBC (Cipher Block Chaining) mode with the key and IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad_text(data))  # Encrypt the data with padding
    
    # Write the IV and the encrypted data to the output file.
    output_file = os.path.join(OUTPUT_PATH, output_filename)
    with open(output_file, 'wb') as f:
        f.write(iv)  # Save the IV for decryption.
        f.write(encrypted_data)  # Save the encrypted content
    
    return key  # Return key for decryption

# Decrypt a file using DES
def decrypt_file(input_filename, output_filename, key):
    # Construct the input file path and read its contents as binary data
    input_file = os.path.join(OUTPUT_PATH, input_filename)
    with open(input_file, 'rb') as f:
        iv = f.read(8)  # The first 8 bytes represent the IV
        encrypted_data = f.read()  # The rest of the file is the encrypted data
    
    # Decrypt data
    # Create a DES cipher object in CBC mode with the same key and IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = remove_padding(cipher.decrypt(encrypted_data))  # Decrypt and remove padding
    
    # Write the decrypted data to the output file.
    output_file = os.path.join(OUTPUT_PATH, output_filename)
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)  # Save the decrypted plaintext file

if __name__ == "__main__":
    # Create a test file
    test_content = b"Hello, this is a test message!"  # Test data in binary format
    with open(os.path.join(INPUT_PATH, 'original.txt'), 'wb') as f:
        f.write(test_content)
    
    print(f"Input directory: {INPUT_PATH}")
    print(f"Output directory: {OUTPUT_PATH}")
    
    # Encrypt and decrypt
    key = encrypt_file('original.txt', 'encrypted.bin')  # Encrypt the test file and get the key
    decrypt_file('encrypted.bin', 'decrypted.txt', key)  # Decrypt the file using the key
    
    print("\nFiles created:")
    print(f"Original: {os.path.join(INPUT_PATH, 'original.txt')}")  # Path of the original file
    print(f"Encrypted: {os.path.join(OUTPUT_PATH, 'encrypted.bin')}")  # Path of the encrypted file
    print(f"Decrypted: {os.path.join(OUTPUT_PATH, 'decrypted.txt')}")  # Path of the decrypted file
