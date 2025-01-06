# File Encryption and Decryption with Symmetric and Asymmetric Techniques
<h3 align="center">Ahmed Walid</h3>

## About The Project
This project demonstrates the implementation of cryptographic principles, including file encryption and decryption using symmetric and asymmetric encryption techniques. It also explores secure key distribution and session management.

## Features

1.  Implementation of file encryption and decryption using DES in CBC mode.
2.  Two-process system for file encryption and decryption.
3.  Needham-Schroeder protocol for symmetric key distribution.
4.  Implementation of RSA for public key encryption and decryption.
5.  The use of Diffie-Hellman for secure session key agreement.

----------

## Project Structure

### Part 1: Symmetric Encryption with DES

#### File: `DES.py`

This script handles file encryption and decryption using the DES algorithm in CBC mode.

#### Key Functions:

1.  **`pad_text`**: Adds padding to plaintext to meet DES block size requirements.
2.  **`remove_padding`**: Removes padding from decrypted text.
3.  **`encrypt_file`**:
    -   Generates a symmetric key and IV.
    -   Encrypts a file using DES in CBC mode.
    -   Writes the encrypted content to an output file.
4.  **`decrypt_file`**:
    -   Reads the IV and encrypted content.
    -   Decrypts the file using the symmetric key.

#### How to Run:

1.  Place the input file in the designated `input` directory.
2.  Run the script. The key and IV are displayed in the console.
3.  The encrypted file will be saved in the `output` directory.
4.  The decryption process reads the key and outputs the decrypted file in the `output` directory.

#### Example:

```bash
python DES.py

```

----------

### Part 2: Symmetric Key Distribution with KDC

#### File: `KDC.py`

This script implements a Key Distribution Center (KDC) following the Needham-Schroeder protocol.

#### Key Functions:

1.  **`register_client`**: Registers clients with the KDC.
2.  **`create_nonce`**: Generates a unique nonce.
3.  **`create_session_key`**: Generates a random session key.
4.  **`request_session`**:
    -   Validates client credentials.
    -   Generates a session key for communication.
    -   Creates messages for both clients and an encrypted ticket for the recipient.
5.  **Client Class**:
    -   Handles session requests and message verification.

#### How to Run:

1.  Register clients with the KDC using the `register_client` method.
2.  Use the `request_session` method to establish communication between clients.
3.  Verify messages using the `verify_message` method.

#### Example:

```bash
python KDC.py

```

----------

### Part 3: Asymmetric Encryption with RSA and Diffie-Hellman Key Exchange

#### File: `RSADH.py`

This script implements:

1.  RSA encryption and decryption for file content.
2.  Diffie-Hellman key exchange for secure session key agreement.

#### Key Functions:

1.  **`generate_key_pair`**: Generates RSA key pairs and saves them to files.
2.  **`load_key`**: Loads an RSA key from a file.
3.  **`encrypt_file`**:
    -   Encrypts a file using RSA for the session key and AES for the file content.
4.  **`decrypt_file`**:
    -   Decrypts the session key using RSA.
    -   Decrypts the file content using AES.
5.  **`implement_diffie_hellman`**:
    -   Implements Diffie-Hellman key exchange to generate a shared secret between two parties.

#### How to Run:

1.  Generate RSA key pairs using `generate_key_pair`.
2.  Use the public key of the recipient to encrypt the file.
3.  Decrypt the file using the private key of the recipient.
4.  Optionally, use the `implement_diffie_hellman` function for session key agreement.

#### Example:

```bash
python RSADH.py

```

----------

## Algorithms Used

### DES (Data Encryption Standard)

-   A symmetric key algorithm.
-   Operates in CBC mode for added security.
-   Requires padding to process plaintext.

### RSA (Rivest-Shamir-Adleman)

-   An asymmetric encryption algorithm.
-   Used for secure key exchange and file encryption.

### Diffie-Hellman Key Exchange

-   Facilitates secure session key generation over an insecure channel.
-   Ensures both parties derive the same shared secret.

### Needham-Schroeder Protocol

-   Provides secure symmetric key distribution using a trusted third party (KDC).
-   Ensures freshness of communication with nonce values.

----------
