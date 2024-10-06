# Decryption of affine cipher
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"


# Helper functions
def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_encrypt(plain_text, a, b):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            x = ord(char) - ord('a')  # Convert to numeric (a=0, b=1, ..., z=25)
            y = (a * x + b) % 26  # Apply encryption formula
            encrypted_text += chr(y + ord('A'))  # Convert back to uppercase letter
        else:
            encrypted_text += char  # Non-alphabetic characters remain unchanged
    return encrypted_text

# Function to decrypt using affine cipher
def affine_decrypt(ciphertext, a, b):
    decrypted_text = ""
    a_inv = mod_inverse(a, 26)  # Find modular inverse of a
    if a_inv is None:
        return None  # No valid modular inverse

    for char in ciphertext:
        if char.isalpha():
            y = ord(char) - ord('A')  # Convert to numeric (A=0, B=1, ..., Z=25)
            x = (a_inv * (y - b)) % 26  # Apply decryption formula
            decrypted_text += chr(x + ord('A'))  # Convert back to letter
        else:
            decrypted_text += char  # Non-alphabetic characters remain unchanged

    return decrypted_text
def find_a_b():
    plaintext = "ab"
    expected_ciphertext = "GL"
    for a in range(1, 26):
        if mod_inverse(a, 26) is not None:  # a must be coprime with 26
            for b in range(26):
                encrypted = affine_encrypt(plaintext, a, b)
                if encrypted == expected_ciphertext:
                    return a, b
    return None, None

# Affine cipher decryption parameters (from "ab" -> "GL")
a, b = find_a_b()


# Decrypt the given ciphertext
plaintext = affine_decrypt(ciphertext, a, b)
print("Decrypted text:", plaintext)
