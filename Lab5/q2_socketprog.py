import socket
import threading

# Hash function
def custom_hash(input_string):
    hash_value = 5381  # Initial hash value

    for char in input_string:
        hash_value = (hash_value * 33) + ord(char)
        hash_value ^= (hash_value >> 16)
        hash_value = ((hash_value << 13) | (hash_value >> (32 - 13))) & 0xFFFFFFFF

    return hash_value & 0xFFFFFFFF

# Server function
def start_server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024).decode()
                print(f"Received data: {data}")
                hash_value = custom_hash(data)
                conn.sendall(str(hash_value).encode())
                print(f"Sent hash: {hash_value}")

# Client function
def start_client(host='127.0.0.1', port=65432, message="Hello, World!"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message.encode())
        print(f"Sent message: {message}")
        received_hash = int(s.recv(1024).decode())
        print(f"Received hash: {received_hash}")

        # Verify integrity
        computed_hash = custom_hash(message)
        print(f"Computed hash: {computed_hash}")

        if received_hash == computed_hash:
            print("Data integrity verified: Hashes match.")
        else:
            print("Data integrity verification failed: Hashes do not match.")

# Main function to run either the server or client
def main():
    choice = input("Enter 's' to start server or 'c' to start client: ").strip().lower()
    if choice == 's':
        start_server()
    elif choice == 'c':
        message = input("Enter message to send: ")
        start_client(message=message)
    else:
        print("Invalid choice! Please enter 's' for server or 'c' for client.")

if __name__ == "__main__":
    main()
