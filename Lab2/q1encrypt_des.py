from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Define the key and ensure it's 8 bytes long (64 bits for DES)
key = b'A1B2C3D4'

# DES requires an 8-byte block size for plaintext, and ECB mode doesn't use an IV
block_size = 8

# The plaintext message
plaintext = "Confidential Data"


# Encrypting the message
def encrypt_des(plaintext, key):
    # Create a DES cipher object in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)

    # Pad the plaintext to match the DES block size
    padded_plaintext = pad(plaintext.encode(), block_size)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    return ciphertext


# Decrypting the message
def decrypt_des(ciphertext, key):
    # Create a DES cipher object in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)

    # Decrypt the ciphertext
    decrypted_padded_text = cipher.decrypt(ciphertext)

    # Unpad the plaintext after decryption
    plaintext = unpad(decrypted_padded_text, block_size)

    return plaintext.decode()


# Encrypt the message
ciphertext = encrypt_des(plaintext, key)
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt the ciphertext
decrypted_message = decrypt_des(ciphertext, key)
print("Decrypted message:", decrypted_message)
