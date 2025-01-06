import random
import time
import base64
from dataclasses import dataclass

@dataclass
class Message:
    content: str
    nonce: int
    timestamp: float

class KDC:
    def __init__(self):
        # Store client passwords (in real system, these would be encrypted)
        self.client_passwords = {}
        # Store session keys between clients
        self.session_keys = {}
        # Store used nonces to prevent replay attacks
        self.used_nonces = set()
    
    def register_client(self, client_name: str, password: str):
        """Register a new client with their password"""
        self.client_passwords[client_name] = password
        print(f"Registered client: {client_name}")

    def create_nonce(self) -> int:
        """Create a new unique nonce"""
        while True:
            nonce = random.randint(1000, 9999)
            if nonce not in self.used_nonces:
                self.used_nonces.add(nonce)
                return nonce

    def create_session_key(self) -> str:
        """Create a random session key"""
        random_bytes = random.randbytes(8)
        return base64.b64encode(random_bytes).decode()

    def create_ticket(self, session_key: str, client_b: str, nonce: int) -> Message:
        """
        Create a ticket for client B containing:
        - The session key
        - A nonce for freshness
        - Current timestamp
        """
        return Message(
            content=session_key,
            nonce=nonce,
            timestamp=time.time()
        )

    def request_session(self, client_a: str, client_b: str, password_a: str, nonce_a: int) -> tuple[str, Message, Message]:
        """
        Handle session request from client A to communicate with client B
        
        Returns:
        - session_key: The key both clients will use
        - message_for_a: Message containing session info for client A
        - ticket_for_b: Encrypted ticket for client B
        """
        # Verify client A's password
        if self.client_passwords.get(client_a) != password_a:
            raise ValueError("Invalid password")

        # Check if both clients are registered
        if client_b not in self.client_passwords:
            raise ValueError("Client B not registered")

        # Verify nonce hasn't been used before
        if nonce_a in self.used_nonces:
            raise ValueError("Nonce already used")
        self.used_nonces.add(nonce_a)

        # Generate session key
        session_key = self.create_session_key()
        self.session_keys[(client_a, client_b)] = session_key

        # Create timestamp for message freshness
        current_time = time.time()

        # Create ticket for client B
        ticket_for_b = self.create_ticket(
            session_key=session_key,
            client_b=client_b,
            nonce=self.create_nonce()
        )

        # Create message for client A
        message_for_a = Message(
            content=f"Session established with {client_b}",
            nonce=nonce_a,  # Return original nonce to prove message freshness
            timestamp=current_time
        )

        return session_key, message_for_a, ticket_for_b

class Client:
    def __init__(self, name: str, password: str):
        self.name = name
        self.password = password
        self.session_keys = {}
        self.nonces = set()

    def create_session_request(self, other_client: str) -> tuple[str, str, int]:
        """
        Create a request to establish session with another client
        Returns: (our_name, other_client_name, nonce)
        """
        nonce = random.randint(1000, 9999)
        self.nonces.add(nonce)
        return self.name, other_client, nonce

    def verify_message(self, message: Message) -> bool:
        """Verify a message is fresh and has our nonce"""
        # Check if nonce was one we generated
        if message.nonce not in self.nonces:
            return False
        
        # Check if message is recent (within last 5 minutes)
        if time.time() - message.timestamp > 300:  # 300 seconds = 5 minutes
            return False
            
        return True

# Example usage:
if __name__ == "__main__":
    # Create KDC
    kdc = KDC()

    # Register two clients
    kdc.register_client("Alice", "password123")
    kdc.register_client("Bob", "password456")

    # Create client objects
    alice = Client("Alice", "password123")
    bob = Client("Bob", "password456")

    try:
        # Alice wants to talk to Bob
        print("\nAlice requesting session with Bob...")
        
        # Step 1: Alice creates session request
        alice_name, bob_name, nonce = alice.create_session_request("Bob")
        print(f"Alice generated nonce: {nonce}")

        # Step 2: Alice sends request to KDC
        session_key, msg_for_alice, ticket_for_bob = kdc.request_session(
            alice_name, 
            bob_name,
            alice.password,
            nonce
        )

        # Step 3: Alice verifies the response
        if alice.verify_message(msg_for_alice):
            print("Alice verified KDC response!")
            print(f"Session key: {session_key}")
            print(f"Message for Alice: {msg_for_alice}")
            print(f"Ticket for Bob: {ticket_for_bob}")
        else:
            print("Message verification failed!")

    except Exception as e:
        print(f"Error: {str(e)}")