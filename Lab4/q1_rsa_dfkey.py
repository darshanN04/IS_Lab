import random
from sympy import mod_inverse, nextprime

class RSA:
    def __init__(self, bit_length=512):
        # Generate two large prime numbers p and q
        p = nextprime(random.getrandbits(bit_length))
        q = nextprime(random.getrandbits(bit_length))
        self.n = p * q  # RSA modulus
        self.phi_n = (p - 1) * (q - 1)  # Euler's totient function
        self.e = 65537  # Public exponent (commonly used)
        self.d = mod_inverse(self.e, self.phi_n)  # Private exponent

    def encrypt(self, plaintext):
        # Ciphertext c = m^e mod n
        ciphertext = pow(plaintext, self.e, self.n)
        return ciphertext

    def decrypt(self, ciphertext):
        # Plaintext m = c^d mod n
        plaintext = pow(ciphertext, self.d, self.n)
        return plaintext

    def multiply_encrypted(self, c1, c2):
        # Homomorphic multiplication: c1 * c2 mod n
        return (c1 * c2) % self.n

# Create an RSA instance
rsa = RSA()

# Encrypt two integers
plaintext1 = 7
plaintext2 = 3
ciphertext1 = rsa.encrypt(plaintext1)
ciphertext2 = rsa.encrypt(plaintext2)

# Print the ciphertexts
print("Ciphertext 1:", ciphertext1)
print("Ciphertext 2:", ciphertext2)

# Perform multiplication on the encrypted integers
encrypted_product = rsa.multiply_encrypted(ciphertext1, ciphertext2)

# Print the result of the multiplication in encrypted form
print("Encrypted product:", encrypted_product)

# Decrypt the result of the multiplication
decrypted_product = rsa.decrypt(encrypted_product)

# Verify that it matches the product of the original integers
print("Decrypted product:", decrypted_product)
print("Original product:", plaintext1 * plaintext2)
