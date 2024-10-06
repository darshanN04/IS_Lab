from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify, unhexlify

# Step 1: Generate RSA key pair (public and private key)
key = RSA.generate(2048)  # 2048-bit key for RSA
public_key = key.publickey()

# Step 2: Extract public key values (n, e) and private key values (n, d)
n = key.n
e = key.e
d = key.d

# Display the public and private key components
print(f"Public Key (n, e): ({n}, {e})")
print(f"Private Key (n, d): ({n}, {d})")

# Step 3: Encrypt the message using the public key
message = "Asymmetric Encryption".encode('utf-8')
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(message)

# Step 4: Output the ciphertext in hexadecimal format
print(f"Ciphertext (hex): {hexlify(ciphertext).decode()}")

# Step 5: Decrypt the ciphertext using the private key
cipher = PKCS1_OAEP.new(key)  # Use the private key for decryption
decrypted_message = cipher.decrypt(ciphertext)

# Step 6: Output the decrypted message
print(f"Decrypted Message: {decrypted_message.decode()}")
