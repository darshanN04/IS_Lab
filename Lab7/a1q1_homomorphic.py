import random
import math

class ElGamal:
    def __init__(self, bit_length=512):
        self.p = self.generate_prime(bit_length)
        self.g = random.randint(2, self.p - 1)
        self.x = random.randint(1, self.p - 2)  # Private key
        self.y = pow(self.g, self.x, self.p)  # Public key (y = g^x mod p)
    
    def generate_prime(self, bit_length):
        while True:
            prime_candidate = random.getrandbits(bit_length)
            if self.is_prime(prime_candidate):
                return prime_candidate
    
    def is_prime(self, n, k=5):
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
        s = 0
        d = n - 1
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def encrypt(self, m):
        """Encrypt message m using public key (g, y, p)."""
        k = random.randint(1, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.y, k, self.p)) % self.p
        return (c1, c2)
    
    def decrypt(self, c):
        """Decrypt ciphertext c = (c1, c2) using private key (x, p)."""
        c1, c2 = c
        s = pow(c1, self.x, self.p)
        m = (c2 * pow(s, self.p - 2, self.p)) % self.p  # Using Fermat's Little Theorem for modular inverse
        return m
    
    def homomorphic_multiply(self, c1, c2):
        """Homomorphic multiplication of two ciphertexts."""
        c1_new = (c1[0] * c2[0]) % self.p
        c2_new = (c1[1] * c2[1]) % self.p
        return (c1_new, c2_new)

# Create an ElGamal encryption scheme instance
elgamal = ElGamal()

# Encrypt two integers
m1 = 7
m2 = 3

c1 = elgamal.encrypt(m1)
c2 = elgamal.encrypt(m2)

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

# Perform homomorphic multiplication
c_product = elgamal.homomorphic_multiply(c1, c2)

print(f"Ciphertext of product (encrypted): {c_product}")

# Decrypt the result
decrypted_product = elgamal.decrypt(c_product)

print(f"Decrypted product: {decrypted_product}")
