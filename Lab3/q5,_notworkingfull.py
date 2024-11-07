from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from os import urandom
from time import time

# AES encryption function
def aes_encrypt(file_data, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
    return cipher_aes.nonce, ciphertext, tag

# AES decryption function
def aes_decrypt(nonce, ciphertext, tag, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)

# RSA key generation (2048-bit)
def generate_rsa_keys():
    start_time = time()
    rsa_key = RSA.generate(2048)
    rsa_key_time = time() - start_time
    print(f"RSA Key Generation Time: {rsa_key_time:.4f} seconds")
    return rsa_key

# ECC key generation (secp256r1)
def generate_ecc_keys():
    start_time = time()
    ecc_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    ecc_key_time = time() - start_time
    print(f"ECC Key Generation Time: {ecc_key_time:.4f} seconds")
    return ecc_key

# RSA encryption
def rsa_encrypt_file(file_data, rsa_public_key):
    aes_key = urandom(32)  # AES-256 key
    nonce, ciphertext, tag = aes_encrypt(file_data, aes_key)

    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    return enc_aes_key, nonce, ciphertext, tag

# ECC encryption
def ecc_encrypt_file(file_data, ecc_private_key, ecc_public_key):
    aes_key = urandom(32)  # AES-256 key
    nonce, ciphertext, tag = aes_encrypt(file_data, aes_key)

    # Encrypt AES key using ECDH-derived key
    shared_key = ecc_private_key.exchange(ec.ECDH(), ecc_public_key)
    derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b'file_transfer', backend=default_backend()).derive(shared_key)

    enc_aes_key = derived_key  # Use derived key directly for simplicity
    return enc_aes_key, nonce, ciphertext, tag

# RSA decryption
def rsa_decrypt_file(enc_aes_key, nonce, ciphertext, tag, rsa_private_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    return aes_decrypt(nonce, ciphertext, tag, aes_key)

# ECC decryption
def ecc_decrypt_file(enc_aes_key, nonce, ciphertext, tag, ecc_private_key, ecc_public_key):
    # Derive the AES key using the recipient's private key
    shared_key = ecc_private_key.exchange(ec.ECDH(), ecc_public_key)
    derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b'file_transfer', backend=default_backend()).derive(shared_key)
    return aes_decrypt(nonce, ciphertext, tag, derived_key)

# Measure performance of encryption and decryption for RSA and ECC
def measure_performance(file_data):
    # Generate RSA and ECC keys
    rsa_key = generate_rsa_keys()
    ecc_key = generate_ecc_keys()

    rsa_public_key = rsa_key.publickey()
    ecc_public_key = ecc_key.public_key()

    # RSA Encryption
    start_time = time()
    enc_aes_key_rsa, nonce_rsa, ciphertext_rsa, tag_rsa = rsa_encrypt_file(file_data, rsa_public_key)
    rsa_encrypt_time = time() - start_time
    print(f"RSA Encryption Time (1MB): {rsa_encrypt_time:.4f} seconds")

    # RSA Decryption
    start_time = time()
    decrypted_data_rsa = rsa_decrypt_file(enc_aes_key_rsa, nonce_rsa, ciphertext_rsa, tag_rsa, rsa_key)
    rsa_decrypt_time = time() - start_time
    print(f"RSA Decryption Time (1MB): {rsa_decrypt_time:.4f} seconds")

    # ECC Encryption
    start_time = time()
    enc_aes_key_ecc, nonce_ecc, ciphertext_ecc, tag_ecc = ecc_encrypt_file(file_data, ecc_key, ecc_public_key)
    ecc_encrypt_time = time() - start_time
    print(f"ECC Encryption Time (1MB): {ecc_encrypt_time:.4f} seconds")

    # ECC Decryption
    start_time = time()
    decrypted_data_ecc = ecc_decrypt_file(enc_aes_key_ecc, nonce_ecc, ciphertext_ecc, tag_ecc, ecc_key, ecc_public_key)
    ecc_decrypt_time = time() - start_time
    print(f"ECC Decryption Time (1MB): {ecc_decrypt_time:.4f} seconds")

    # Verify that decrypted data matches the original data
    assert decrypted_data_rsa == file_data, "RSA Decryption failed!"
    assert decrypted_data_ecc == file_data, "ECC Decryption failed!"

# Main function to test the secure file transfer system
if __name__ == "__main__":
    file_data = urandom(1 * 1024 * 1024)  # 1 MB sample file
    measure_performance(file_data)
