import random
import math

def egcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x

def modinv(a, m):
    """Modular inverse using the Extended Euclidean Algorithm."""
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

class RSA:
    def __init__(self, bit_length=512):
        self.p = self.generate_prime(bit_length // 2)
        self.q = self.generate_prime(bit_length // 2)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = 65537  # Commonly used value for e
        self.d = modinv(self.e, self.phi_n)
    
    def generate_prime(self, bit_length):
        while True:
            prime_candidate = random.getrandbits(bit_length)
            if self.is_prime(prime_candidate):
                return prime_candidate
    
    def is_prime(self, n, k=5):
        """Miller-Rabin primality test."""
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
        """Encrypt message m using public key (e, n)."""
        return pow(m, self.e, self.n)
    
    def decrypt(self, c):
        """Decrypt ciphertext c using private key (d, n)."""
        return pow(c, self.d, self.n)

# Create an RSA encryption scheme instance
rsa = RSA()

# Encrypt two integers
m1 = 7
m2 = 3

c1 = rsa.encrypt(m1)
c2 = rsa.encrypt(m2)

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

# Perform homomorphic multiplication
c_product = (c1 * c2) % rsa.n

print(f"Ciphertext of product (encrypted): {c_product}")

# Decrypt the result
decrypted_product = rsa.decrypt(c_product)

print(f"Decrypted product: {decrypted_product}")
