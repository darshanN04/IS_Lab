from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex("FEDCBA9876543210FEDCBA98765432101234567890ABCDEF0123456789ABCDEF") # 32 hex characters = 16 bytes (AES-192 requires 24 bytes)
plaintext = "Top Secret Data"

# AES block size
block_size = 16  # AES block size is 16 bytes

# Encryption
cipher_encrypt = AES.new(key, AES.MODE_CBC)  # AES-192 in CBC mode
iv = cipher_encrypt.iv  # Initialization Vector
padded_plaintext = pad(plaintext.encode(), block_size)  # Pad the plaintext
ciphertext = cipher_encrypt.encrypt(padded_plaintext)  # Encrypt the padded plaintext

# Decryption
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)  # AES decryption in CBC mode, using the same IV
decrypted_padded_plaintext = cipher_decrypt.decrypt(ciphertext)  # Decrypt the ciphertext
decrypted_plaintext = unpad(decrypted_padded_plaintext, block_size).decode()  # Unpad the decrypted text

print("Cipher: ", ciphertext.hex())
print("Plain: ", decrypted_plaintext)  # Return the ciphertext in hex format and the decrypted plaintext
