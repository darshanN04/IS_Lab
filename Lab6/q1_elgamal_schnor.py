from Crypto.Random import random
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import hashlib


class ElGamalSignature:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.generate_keys()

    def generate_keys(self):
        # Step 1: Select a large prime p
        self.p = getPrime(self.key_size)

        # Step 2: Select a generator g of the multiplicative group of integers modulo p
        # For simplicity, we choose g = 2
        self.g = 2

        # Step 3: Select a private key x randomly from {1, 2, ..., p-2}
        self.x = random.StrongRandom().randint(1, self.p - 2)

        # Step 4: Compute the public key y = g^x mod p
        self.y = pow(self.g, self.x, self.p)

        print("ElGamal Key Generation Complete.")
        print(f"Public Key (p, g, y):\n p = {self.p}\n g = {self.g}\n y = {self.y}\n")
        print(f"Private Key x: {self.x}\n")

    def sign(self, message):
        # Hash the message
        hash_obj = hashlib.sha256()
        hash_obj.update(message.encode('utf-8'))
        m = bytes_to_long(hash_obj.digest())

        # Choose a random k such that gcd(k, p-1) = 1
        while True:
            k = random.StrongRandom().randint(1, self.p - 2)
            if inverse(k, self.p - 1):
                break

        # Compute r = g^k mod p
        r = pow(self.g, k, self.p)

        # Compute s = k^-1 * (m - x * r) mod (p-1)
        try:
            k_inv = inverse(k, self.p - 1)
        except ValueError:
            # If inverse doesn't exist, choose another k
            return self.sign(message)

        s = (k_inv * (m - self.x * r)) % (self.p - 1)

        signature = (r, s)
        print(f"Signature: r = {r}, s = {s}\n")
        return signature

    def verify(self, message, signature):
        r, s = signature

        # Check that 0 < r < p
        if not (0 < r < self.p):
            print("Invalid signature: r out of range.")
            return False

        # Hash the message
        hash_obj = hashlib.sha256()
        hash_obj.update(message.encode('utf-8'))
        m = bytes_to_long(hash_obj.digest())

        # Compute left side: y^r * r^s mod p
        lhs = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p

        # Compute right side: g^m mod p
        rhs = pow(self.g, m, self.p)

        print(f"Verification:\n y^r * r^s mod p = {lhs}\n g^m mod p = {rhs}\n")

        return lhs == rhs


def main():
    # Initialize ElGamal Signature Scheme
    elgamal = ElGamalSignature(key_size=2048)

    # Alice signs a document
    message = "This is a confidential legal document."
    print(f"Original Message: {message}")
    signature = elgamal.sign(message)

    # Bob verifies the signature
    print("Verifying Signature...")
    is_valid = elgamal.verify(message, signature)
    print(f"Signature valid: {is_valid}\n")

    # Demonstrate signature verification failure (tampered message)
    tampered_message = "This is a tampered legal document."
    print(f"Tampered Message: {tampered_message}")
    print("Verifying Signature for Tampered Message...")
    is_valid_tampered = elgamal.verify(tampered_message, signature)
    print(f"Signature valid: {is_valid_tampered}\n")


if __name__ == "__main__":
    main()
