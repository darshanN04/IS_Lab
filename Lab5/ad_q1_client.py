import socket
import hashlib
import math

def compute_hash(message):
    """
    Computes the SHA-256 hash of the given message.

    Args:
        message (bytes): The message to hash.

    Returns:
        str: The hexadecimal representation of the hash.
    """
    sha256 = hashlib.sha256()
    sha256.update(message)
    return sha256.hexdigest()

def split_message(message, chunk_size=1024):
    """
    Splits the message into chunks of specified size.

    Args:
        message (bytes): The message to split.
        chunk_size (int): The size of each chunk in bytes.

    Returns:
        List[bytes]: A list of message chunks.
    """
    return [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

def start_client(server_host='127.0.0.1', server_port=65432, message="Hello, this is a test message sent in multiple parts!"):
    """
    Connects to the server, sends the message in chunks, receives the hash, and verifies integrity.

    Args:
        server_host (str): The server's hostname or IP address.
        server_port (int): The server's port number.
        message (str): The message to send.
    """
    message_bytes = message.encode()
    chunks = split_message(message_bytes, chunk_size=1024)
    total_chunks = len(chunks)

    print(f"Total chunks to send: {total_chunks}")

    # Compute local hash
    local_hash = compute_hash(message_bytes)
    print(f"Local Computed Hash: {local_hash}")

    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))
        print(f"Connected to server {server_host}:{server_port}")

        # Send each chunk
        for idx, chunk in enumerate(chunks):
            s.sendall(chunk)
            print(f"Sent chunk {idx + 1}/{total_chunks}: {chunk}")

        # Send end of message indicator
        s.sendall(b'<END>')
        print("Sent <END> indicator to signify end of message.")

        # Receive the hash from the server
        received_hash = s.recv(1024).decode()
        print(f"Received Hash from Server: {received_hash}")

    # Verify integrity
    if received_hash == local_hash:
        print("Data integrity verified: Hashes match.")
    else:
        print("Data integrity verification failed: Hashes do not match.")

if __name__ == "__main__":
    # Example usage
    user_message = input("Enter the message to send: ")
    start_client(message=user_message)
