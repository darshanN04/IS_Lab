from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify, hexlify

# Define the DES key (must be 8 bytes for DES)
key = bytes.fromhex("A1B2C3D4E5F60708")

# Convert the hex strings for the blocks to byte format
block1 = unhexlify("54686973206973206120636f6e666964656e7469616c206d657373616765")
block2 = unhexlify("416e64207468697320697320746865207365636f6e6420626c6f636b")

# Create a DES cipher object in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Since DES requires data to be a multiple of 8 bytes, we need to pad the blocks
block1_padded = pad(block1, DES.block_size)
block2_padded = pad(block2, DES.block_size)

# Encrypt the blocks
ciphertext_block1 = cipher.encrypt(block1_padded)
ciphertext_block2 = cipher.encrypt(block2_padded)

# Output the ciphertext in hexadecimal format
print(f"Ciphertext for Block1 (hex): {ciphertext_block1.hex()}")
print(f"Ciphertext for Block2 (hex): {ciphertext_block2.hex()}")

# Decrypt the ciphertext to retrieve the original blocks
decrypted_block1_padded = cipher.decrypt(ciphertext_block1)
decrypted_block2_padded = cipher.decrypt(ciphertext_block2)

# Unpad the decrypted data to retrieve the original plaintext
decrypted_block1 = unpad(decrypted_block1_padded, DES.block_size)
decrypted_block2 = unpad(decrypted_block2_padded, DES.block_size)

# Output the decrypted plaintext (hex and readable string format)
print(f"Decrypted Block1 (plaintext): {decrypted_block1.decode()}")
print(f"Decrypted Block2 (plaintext): {decrypted_block2.decode()}")
