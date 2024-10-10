import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

# Function to generate Diffie-Hellman parameters and keys
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

# Function to generate private and public keys for a peer
def generate_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Function to compute the shared secret
def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

# Main function to simulate the Diffie-Hellman key exchange
# Generate parameters (this can be shared by both peers)
start_time = time.time()
parameters = generate_dh_parameters()
parameters_time = time.time() - start_time

# Generate keys for Peer 1
start_time = time.time()
private_key_peer1, public_key_peer1 = generate_keys(parameters)
peer1_keygen_time = time.time() - start_time

# Generate keys for Peer 2
start_time = time.time()
private_key_peer2, public_key_peer2 = generate_keys(parameters)
peer2_keygen_time = time.time() - start_time

# Exchange keys and compute shared secret for Peer 1
start_time = time.time()
shared_secret_peer1 = compute_shared_secret(private_key_peer1, public_key_peer2)
peer1_secret_time = time.time() - start_time

# Exchange keys and compute shared secret for Peer 2
start_time = time.time()
shared_secret_peer2 = compute_shared_secret(private_key_peer2, public_key_peer1)
peer2_secret_time = time.time() - start_time

# Ensure both peers have the same shared secret
assert shared_secret_peer1 == shared_secret_peer2, "Shared secrets do not match!"

# Print time measurements
print(f"Parameter generation time: {parameters_time:.6f} seconds")
print(f"Peer 1 key generation time: {peer1_keygen_time:.6f} seconds")
print(f"Peer 2 key generation time: {peer2_keygen_time:.6f} seconds")
print(f"Peer 1 shared secret computation time: {peer1_secret_time:.6f} seconds")
print(f"Peer 2 shared secret computation time: {peer2_secret_time:.6f} seconds")
print(f"Shared Secret (hex): {shared_secret_peer1.hex()}")


