import socket
import hashlib

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

def start_server(host='0.0.0.0', port=65432):
    """
    Starts the server to receive messages, compute hash, and send it back.

    Args:
        host (str): The hostname or IP address to bind the server.
        port (int): The port number to bind the server.
    """
    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                received_data = b''
                while True:
                    data = conn.recv(1024)
                    if not data:
                        # Connection closed by client
                        break
                    if data == b'<END>':
                        # End of message
                        break
                    received_data += data
                    print(f"Received chunk: {data}")

                print(f"Complete message received ({len(received_data)} bytes). Computing hash...")
                message_hash = compute_hash(received_data)
                print(f"Computed Hash: {message_hash}")

                # Send the hash back to the client
                conn.sendall(message_hash.encode())
                print("Hash sent back to the client.\n")

if __name__ == "__main__":
    start_server()
