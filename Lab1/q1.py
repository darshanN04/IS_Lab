# Helper function to convert characters to positions (A=0, B=1, ..., Z=25)
def char_to_pos(char):
    return ord(char) - ord('A')


# Helper function to convert positions to characters
def pos_to_char(pos):
    return chr(pos + ord('A'))


# Encrypt and Decrypt functions for each cipher

# Additive Cipher with Key = 20
def additive_encrypt(plaintext, key):
    return ''.join([pos_to_char((char_to_pos(char) + key) % 26) for char in plaintext])


def additive_decrypt(ciphertext, key):
    return ''.join([pos_to_char((char_to_pos(char) - key) % 26) for char in ciphertext])


# Multiplicative Cipher with Key = 15
def multiplicative_encrypt(plaintext, key):
    return ''.join([pos_to_char((char_to_pos(char) * key) % 26) for char in plaintext])


def multiplicative_decrypt(ciphertext, key):
    # Find the modular inverse of the key (15) modulo 26
    mod_inverse = None
    for i in range(26):
        if (key * i) % 26 == 1:
            mod_inverse = i
            break
    if mod_inverse is None:
        raise ValueError("No modular inverse for the given key.")

    return ''.join([pos_to_char((char_to_pos(char) * mod_inverse) % 26) for char in ciphertext])


# Affine Cipher with Key = (15, 20)
def affine_encrypt(plaintext, key_mult, key_add):
    return ''.join([pos_to_char((char_to_pos(char) * key_mult + key_add) % 26) for char in plaintext])


def affine_decrypt(ciphertext, key_mult, key_add):
    # Find the modular inverse of the multiplicative key (15) modulo 26
    mod_inverse = None
    for i in range(26):
        if (key_mult * i) % 26 == 1:
            mod_inverse = i
            break
    if mod_inverse is None:
        raise ValueError("No modular inverse for the given key.")

    return ''.join([pos_to_char((mod_inverse * (char_to_pos(char) - key_add)) % 26) for char in ciphertext])


# Main message
plaintext = "IAMLEARNINGINFORMATIONSECURITY".replace(" ", "")

# 1. Additive Cipher with Key = 20
key_additive = 20
ciphertext_additive = additive_encrypt(plaintext, key_additive)
decrypted_additive = additive_decrypt(ciphertext_additive, key_additive)

print("Additive Cipher:")
print("Ciphertext:", ciphertext_additive)
print("Decrypted:", decrypted_additive)

# 2. Multiplicative Cipher with Key = 15
key_multiplicative = 15
ciphertext_multiplicative = multiplicative_encrypt(plaintext, key_multiplicative)
decrypted_multiplicative = multiplicative_decrypt(ciphertext_multiplicative, key_multiplicative)

print("\nMultiplicative Cipher:")
print("Ciphertext:", ciphertext_multiplicative)
print("Decrypted:", decrypted_multiplicative)

# 3. Affine Cipher with Key = (15, 20)
key_affine_mult = 15
key_affine_add = 20
ciphertext_affine = affine_encrypt(plaintext, key_affine_mult, key_affine_add)
decrypted_affine = affine_decrypt(ciphertext_affine, key_affine_mult, key_affine_add)

print("\nAffine Cipher:")
print("Ciphertext:", ciphertext_affine)
print("Decrypted:", decrypted_affine)
