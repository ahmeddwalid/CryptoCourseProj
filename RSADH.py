from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import os

def setup_directories():
    # Define paths
    base_path = os.path.join(os.path.expanduser('~/Koleya/5th Term/Introduction to Cryptography/Coursework Project'), 'CryptoProject')
    input_path = os.path.join(base_path, 'input')
    output_path = os.path.join(base_path, 'output')
    
    # Create directories if they don't exist
    os.makedirs(input_path, exist_ok=True)
    os.makedirs(output_path, exist_ok=True)
    
    return input_path, output_path

def generate_key_pair(bits=2048):
    """
    Generate an RSA key pair and save to files
    
    Args:
        bits (int): Key size in bits (default: 2048)
    Returns:
        tuple: (private_key, public_key) as RSA key objects
    """
    # Generate private key
    private_key = RSA.generate(bits)
    # Extract public key from private key
    public_key = private_key.publickey()
    
    # Save private key to file
    with open("private_key.pem", "wb") as f:
        f.write(private_key.export_key("PEM"))
    
    # Save public key to file
    with open("public_key.pem", "wb") as f:
        f.write(public_key.export_key("PEM"))
    
    return private_key, public_key

def load_key(filename):
    """
    Load an RSA key from a file
    
    Args:
        filename (str): Path to the key file
    Returns:
        RSA key object
    """
    with open(filename, "rb") as f:
        key_data = f.read()
    return RSA.import_key(key_data)

def encrypt_file(input_file, output_file, recipient_public_key):
    """
    Encrypt a file using RSA and AES
    
    Args:
        input_file (str): Path to input file
        output_file (str): Path to output encrypted file
        recipient_public_key (RSA key): Recipient's public key
    """
    # Generate a random session key for AES
    session_key = get_random_bytes(16)  # 128-bit key for AES
    
    # Create RSA cipher object
    rsa_cipher = PKCS1_OAEP.new(recipient_public_key)
    
    # Encrypt the session key with RSA
    encrypted_session_key = rsa_cipher.encrypt(session_key)
    
    # Create AES cipher object (CBC mode with random IV)
    iv = get_random_bytes(16)
    aes_cipher = AES.new(session_key, AES.MODE_CBC, iv)
    
    # Read and encrypt the file
    with open(input_file, 'rb') as f:
        data = f.read()
        
    # Pad the data (required for CBC mode)
    pad_length = 16 - (len(data) % 16)
    data += bytes([pad_length]) * pad_length
    
    # Encrypt the data with AES
    encrypted_data = aes_cipher.encrypt(data)
    
    # Write everything to output file
    with open(output_file, 'wb') as f:
        # Write lengths first (as 4 bytes each)
        f.write(len(encrypted_session_key).to_bytes(4, 'big'))
        f.write(len(iv).to_bytes(4, 'big'))
        # Write the encrypted session key and IV
        f.write(encrypted_session_key)
        f.write(iv)
        # Write the encrypted data
        f.write(encrypted_data)

# Decrypt a file using RSA and AES
def decrypt_file(input_file, output_file, private_key):
    
    with open(input_file, 'rb') as f:
        # Read the lengths
        session_key_length = int.from_bytes(f.read(4), 'big')
        iv_length = int.from_bytes(f.read(4), 'big')
        
        # Read the encrypted session key and IV
        encrypted_session_key = f.read(session_key_length)
        iv = f.read(iv_length)
        
        # Read the encrypted data
        encrypted_data = f.read()
    
    # Create RSA cipher object
    rsa_cipher = PKCS1_OAEP.new(private_key)
    
    # Decrypt the session key
    session_key = rsa_cipher.decrypt(encrypted_session_key)
    
    # Create AES cipher object
    aes_cipher = AES.new(session_key, AES.MODE_CBC, iv)
    
    # Decrypt the data
    decrypted_data = aes_cipher.decrypt(encrypted_data)
    
    # Remove padding
    pad_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_length]
    
    # Write decrypted data to output file
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

# Returns: tuple: (shared_secret_alice, shared_secret_bob)
def implement_diffie_hellman():
    from Crypto.Random.random import randint
    from Crypto.Util.number import getPrime
    
    # Generate prime number p and generator g
    # For demonstration, using smaller numbers. In production, use larger primes
    p = getPrime(512)  # Safe prime
    g = 2  # Common generator
    
    # Generate private keys (random numbers)
    alice_private = randint(2, p-2)
    bob_private = randint(2, p-2)
    
    # Generate public keys
    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)
    
    # Compute shared secrets
    alice_shared_secret = pow(bob_public, alice_private, p)
    bob_shared_secret = pow(alice_public, bob_private, p)
    
    # Convert to bytes for consistency
    shared_secret = alice_shared_secret.to_bytes((alice_shared_secret.bit_length() + 7) // 8, byteorder='big') # Convert to bytes in big endian so the most significant byte is first
    
    # Both shared secrets should be identical
    assert alice_shared_secret == bob_shared_secret
    print(f"\nDiffie-Hellman parameters:")
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")
    print(f"Public keys exchanged successfully!")
    
    return shared_secret, shared_secret

def create_sample_file(input_path):
    """
    Create a sample text file for encryption
    
    Args:
        input_path (str): Path to input directory
    Returns:
        str: Path to created file
    """
    # Sample content with different types of data
    test_content = "Hello This is a Sample text".encode('utf-8')
    
    # Create the file
    file_path = os.path.join(input_path, 'original.txt')
    with open(file_path, 'wb') as f:
        f.write(test_content)
    
    return file_path

def main():
    """
    Example usage of the encryption/decryption functions with file handling
    """
    # Setup directories
    input_path, output_path = setup_directories()
    print(f"\nWorking directories created:")
    print(f"Input directory: {input_path}")
    print(f"Output directory: {output_path}")
    
    # Create sample file
    original_file = create_sample_file(input_path)
    print(f"\nSample file created at: {original_file}")
    
    # Generate key pairs for sender and receiver
    print("\nGenerating RSA key pairs...")
    sender_private, sender_public = generate_key_pair()
    receiver_private, receiver_public = generate_key_pair()
    print("RSA keys generated and saved to current directory")
    
    # Define file paths
    encrypted_file = os.path.join(output_path, 'encrypted.bin')
    decrypted_file = os.path.join(output_path, 'decrypted.txt')
    
    # Encrypt the file
    print("\nEncrypting file...")
    encrypt_file(original_file, encrypted_file, receiver_public)
    print(f"File encrypted and saved to: {encrypted_file}")
    
    # Decrypt the file
    print("\nDecrypting file...")
    decrypt_file(encrypted_file, decrypted_file, receiver_private)
    print(f"File decrypted and saved to: {decrypted_file}")
    
    # Verify the decryption
    with open(original_file, 'rb') as f:
        original_content = f.read()
    with open(decrypted_file, 'rb') as f:
        decrypted_content = f.read()
    
    if original_content == decrypted_content:
        print("\nSuccess! The decrypted file matches the original.")
    else:
        print("\nWarning: The decrypted file doesn't match the original!")
    
    # Example: Generate a shared secret using Diffie-Hellman
    print("\nDemonstrating Diffie-Hellman key exchange...")
    alice_secret, bob_secret = implement_diffie_hellman()
    print("Diffie-Hellman shared secret generated successfully!")
    
    # Print summary of created files
    print("\nSummary of created files:")
    print(f"1. Original file: {original_file}")
    print(f"2. Encrypted file: {encrypted_file}")
    print(f"3. Decrypted file: {decrypted_file}")
    print(f"4. Private key: {os.path.join(os.getcwd(), 'private_key.pem')}")
    print(f"5. Public key: {os.path.join(os.getcwd(), 'public_key.pem')}")

if __name__ == "__main__":
    main()