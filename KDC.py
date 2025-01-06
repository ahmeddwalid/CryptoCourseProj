import os
from Crypto.Cipher import DES
import base64
import time
import random
from dataclasses import dataclass
from typing import Dict, Tuple, Optional

@dataclass
class Message:
    """
    Class for representing protocol messages in the Needham-Schroeder protocol.
    Uses Python's dataclass for automatic initialization of attributes.
    
    Attributes:
        content (bytes): The actual message content (could be keys, tickets, etc.)
        timestamp (float): Time when message was created (prevents replay attacks)
        nonce (int): Random number used once (ensures message freshness)
    """
    content: bytes
    timestamp: float
    nonce: int

class KDC:
    """
    Key Distribution Center (KDC) class that manages the central key server.
    Responsible for client registration and session key distribution.
    Implements the server-side of the Needham-Schroeder protocol.
    """
    
    def __init__(self):
        """
        Initialize the KDC with empty databases for storing client information.
        
        Attributes:
            client_keys: Dictionary mapping client IDs to their master keys
            session_keys: Dictionary mapping pairs of clients to their session keys
        """
        self.client_keys: Dict[str, bytes] = {}  
        self.session_keys: Dict[Tuple[str, str], bytes] = {}
        
    def register_client(self, client_id: str) -> bytes:
        """
        Register a new client with the KDC and generate their master key.
        
        Args:
            client_id (str): Unique identifier for the client
            
        Returns:
            bytes: The generated master key for the client
            
        Note: In a real system, this would involve secure key distribution mechanisms
        """
        master_key = os.urandom(8)  # Generate random 64-bit DES key
        self.client_keys[client_id] = master_key
        return master_key
    
    def create_session(self, client_a: str, client_b: str, nonce: int) -> Tuple[bytes, bytes]:
        """
        Create a secure session between two clients following the Needham-Schroeder protocol.
        
        Protocol steps:
        1. Generate session key
        2. Create encrypted ticket for client B
        3. Create encrypted message for client A containing B's ticket
        
        Args:
            client_a (str): ID of the client requesting the session
            client_b (str): ID of the client to communicate with
            nonce (int): Random number provided by client A for freshness
            
        Returns:
            Tuple[bytes, bytes]: (session_key, encrypted_message_for_A)
            
        Raises:
            ValueError: If either client is not registered with the KDC
        """
        # Verify both clients are registered
        if client_a not in self.client_keys or client_b not in self.client_keys:
            raise ValueError("Both clients must be registered")
            
        # Generate new session key for this pair of clients
        session_key = os.urandom(8)  # 64-bit DES key
        self.session_keys[(client_a, client_b)] = session_key
        
        # Get current timestamp for message freshness
        timestamp = time.time()
        
        # Create ticket for client B containing:
        # - Session key
        # - Timestamp
        # - Nonce (to prevent replay attacks)
        ticket_b = Message(
            content=session_key,
            timestamp=timestamp,
            nonce=nonce
        )
        
        # Encrypt ticket for B using B's master key
        # This ensures only B can read the session key
        cipher_b = DES.new(self.client_keys[client_b], DES.MODE_CBC, os.urandom(8))
        encrypted_ticket = cipher_b.encrypt(pad_text(
            str(ticket_b.timestamp).encode() + 
            str(ticket_b.nonce).encode() + 
            ticket_b.content
        ))
        
        # Create message for client A containing:
        # - B's encrypted ticket
        # - Timestamp
        # - Original nonce (proves message freshness)
        message_a = Message(
            content=encrypted_ticket,
            timestamp=timestamp,
            nonce=nonce
        )
        
        # Encrypt message for A using A's master key
        cipher_a = DES.new(self.client_keys[client_a], DES.MODE_CBC, os.urandom(8))
        encrypted_message = cipher_a.encrypt(pad_text(
            str(message_a.timestamp).encode() + 
            str(message_a.nonce).encode() + 
            message_a.content
        ))
        
        return session_key, encrypted_message

class Client:
    """
    Client class representing participants in the protocol.
    Handles client-side operations of the Needham-Schroeder protocol.
    """
    
    def __init__(self, client_id: str, master_key: bytes):
        """
        Initialize a client with their unique ID and master key.
        
        Args:
            client_id (str): Unique identifier for this client
            master_key (bytes): Master key shared with KDC
            
        Attributes:
            session_keys: Dictionary storing session keys for communication with other clients
        """
        self.id = client_id
        self.master_key = master_key
        self.session_keys: Dict[str, bytes] = {}
        
    def request_session(self, kdc: KDC, other_client: str) -> bytes:
        """
        Request a session with another client through the KDC.
        
        Protocol steps:
        1. Generate nonce
        2. Request session from KDC
        3. Decrypt response using master key
        4. Store session key
        
        Args:
            kdc (KDC): Reference to the Key Distribution Center
            other_client (str): ID of the client to communicate with
            
        Returns:
            bytes: The established session key
        """
        # Generate random nonce for message freshness
        nonce = random.randint(1, 1000000)
        
        # Request session key from KDC
        session_key, encrypted_message = kdc.create_session(self.id, other_client, nonce)
        
        # Decrypt KDC's response using our master key
        cipher = DES.new(self.master_key, DES.MODE_CBC, os.urandom(8))
        decrypted_message = remove_padding(cipher.decrypt(encrypted_message))
        
        # Store session key for future communication
        self.session_keys[other_client] = session_key
        return session_key

# Helper functions for DES encryption padding

def pad_text(text: bytes) -> bytes:
    """
    Add PKCS7 padding to make text length a multiple of 8 bytes (DES block size).
    
    Args:
        text (bytes): Original text to pad
        
    Returns:
        bytes: Padded text
    """
    padding_length = 8 - (len(text) % 8)
    return text + bytes([padding_length] * padding_length)

def remove_padding(text: bytes) -> bytes:
    """
    Remove PKCS7 padding from decrypted text.
    
    Args:
        text (bytes): Padded text
        
    Returns:
        bytes: Original text with padding removed
    """
    padding_length = text[-1]
    return text[:-padding_length]

# Example usage and testing
if __name__ == "__main__":
    # Initialize the Key Distribution Center
    kdc = KDC()
    
    # Register two clients (Alice and Bob) with the KDC
    alice_key = kdc.register_client("Alice")
    bob_key = kdc.register_client("Bob")
    
    # Create client instances
    alice = Client("Alice", alice_key)
    bob = Client("Bob", bob_key)
    
    # Demonstrate session establishment
    try:
        # Alice requests session with Bob
        session_key = alice.request_session(kdc, "Bob")
        print(f"Session established between Alice and Bob")
        print(f"Session key (Base64): {base64.b64encode(session_key).decode()}")
    except Exception as e:
        print(f"Session establishment failed: {str(e)}")