from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

plaintext = "Confidential Data"
block = 8
key = b"A1B2C3D4"

def encrypt_des(plaintext, key):
    cipher_key = DES.new(key, DES.MODE_ECB)
    padding_text = pad(plaintext.encode(), block)
    encrypted_text = cipher_key.encrypt(padding_text)
    return encrypted_text


def decrypt_des(ciphertext, key):
    cipher_key = DES.new(key, DES.MODE_ECB)
    decrypted_text = cipher_key.decrypt(ciphertext)
    unpadding_text = unpad(decrypted_text, block)
    return unpadding_text.decode()


cipher = encrypt_des(plaintext, key)
print("cipher text: ", cipher.hex())
plain = decrypt_des(cipher, key)
print("plain text: ", plain)

