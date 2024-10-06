from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b"12345678"  # 4 bytes
plaintext = "Top Secret Data"

# DES block size
block_size = DES.block_size  # DES block size is 16 bytes

# Encryption
cipher_encrypt = DES.new(key, DES.MODE_CBC)  # DES in CBC mode
iv = cipher_encrypt.iv  # Initialization Vector
padded_plaintext = pad(plaintext.encode(), block_size)  # Pad the plaintext
ciphertext = cipher_encrypt.encrypt(padded_plaintext)  # Encrypt the padded plaintext

# Decryption
cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)  # DES decryption in CBC mode, using the same IV
decrypted_padded_plaintext = cipher_decrypt.decrypt(ciphertext)  # Decrypt the ciphertext
decrypted_plaintext = unpad(decrypted_padded_plaintext, block_size).decode()  # Unpad the decrypted text

print("Cipher: ", ciphertext.hex())
print("Plain: ", decrypted_plaintext)  # Return the ciphertext in hex format and the decrypted plaintext
