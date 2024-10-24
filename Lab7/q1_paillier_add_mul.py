import random
import math

def lcm(a, b):
    return abs(a*b) // math.gcd(a, b)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

class Paillier:
    def __init__(self, bit_length=512):
        self.p = self.generate_prime(bit_length // 2)
        self.q = self.generate_prime(bit_length // 2)
        self.n = self.p * self.q
        self.n2 = self.n * self.n
        self.lambda_val = lcm(self.p - 1, self.q - 1)
        self.g = random.randint(1, self.n2)
        self.mu = modinv(self.L_function(pow(self.g, self.lambda_val, self.n2)), self.n)
    
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
    
    def L_function(self, x):
        return (x - 1) // self.n
    
    def encrypt(self, m):
        r = random.randint(1, self.n - 1)
        while math.gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        c = (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2
        return c
    
    def decrypt(self, c):
        x = pow(c, self.lambda_val, self.n2)
        m = (self.L_function(x) * self.mu) % self.n
        return m

# Create a Paillier encryption scheme instance
paillier = Paillier()

# Encrypt two integers
m1 = 25
m2 = 25

c1 = paillier.encrypt(m1)
c2 = paillier.encrypt(m2)

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

# Perform homomorphic addition
c_sum = (c1 * c2) % paillier.n2

print(f"Ciphertext of sum (encrypted): {c_sum}")

# Decrypt the result
decrypted_sum = paillier.decrypt(c_sum)

print(f"Decrypted sum: {decrypted_sum}")
