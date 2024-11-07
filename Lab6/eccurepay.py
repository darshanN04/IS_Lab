from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import binascii
import base64

# Generate ECC keys for signing and encryption
signing_private_key = ECC.generate(curve='P-256')
signing_public_key = signing_private_key.public_key()
encryption_private_key = ECC.generate(curve='P-256')
encryption_public_key = encryption_private_key.public_key()

def decrypt_message(private_key, encrypted_data):
    # Calculate shared secret using the private key and public key
    shared_secret = encryption_public_key.pointQ * private_key.d
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')
    aes_key = SHA256.new(shared_secret_bytes).digest()

    # Create AES cipher and decrypt the message
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(encrypted_data["nonce"]))
    decrypted_data = cipher.decrypt_and_verify(
        base64.b64decode(encrypted_data["ciphertext"]),
        base64.b64decode(encrypted_data["tag"])
    )
    return decrypted_data.decode('utf-8')

# Example of creating an encrypted message for testing
def create_encrypted_message(plain_text, public_key):
    # Calculate shared secret
    shared_secret = public_key.pointQ * encryption_private_key.d
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')
    aes_key = SHA256.new(shared_secret_bytes).digest()

    # Generate a random nonce
    nonce = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    # Encrypt the message
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))

    # Return the encrypted message components in base64
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
    }

# Example usage
plain_text = "123"  # Replace with actual CVV or sensitive data
encrypted_data = create_encrypted_message(plain_text, encryption_public_key)
print(encrypted_data)
# Now decrypt the message
decrypted_cvv = decrypt_message(encryption_private_key, encrypted_data)
print("Decrypted CVV:", decrypted_cvv)
