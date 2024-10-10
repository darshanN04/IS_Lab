from Crypto.Random import random
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import hashlib


class SchnorrSignature:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.generate_keys()

    def generate_keys(self):
        # Step 1: Select a large prime p
        self.p = getPrime(self.key_size)

        # Step 2: Select q such that q divides (p-1), commonly q is a large prime itself
        # For simplicity, let q be a 256-bit prime
        self.q = getPrime(256)
        while (self.p - 1) % self.q != 0:
            self.p = getPrime(self.key_size)
            self.q = getPrime(256)

        # Step 3: Select a generator g of the subgroup of order q
        h = random.StrongRandom().randint(2, self.p - 2)
        self.g = pow(h, (self.p - 1) // self.q, self.p)
        if self.g == 1:
            # Regenerate h if g == 1
            self.generate_keys()
            return

        # Step 4: Select a private key x randomly from {1, 2, ..., q-1}
        self.x = random.StrongRandom().randint(1, self.q - 1)

        # Step 5: Compute the public key y = g^x mod p
        self.y = pow(self.g, self.x, self.p)

        print("Schnorr Signature Key Generation Complete.")
        print(f"Public Key (p, q, g, y):\n p = {self.p}\n q = {self.q}\n g = {self.g}\n y = {self.y}\n")
        print(f"Private Key x: {self.x}\n")

    def sign(self, message):
        # Hash the message
        hash_obj = hashlib.sha256()
        hash_obj.update(message.encode('utf-8'))
        m = bytes_to_long(hash_obj.digest())

        # Choose random k from {1, 2, ..., q-1}
        k = random.StrongRandom().randint(1, self.q - 1)

        # Compute r = g^k mod p
        r = pow(self.g, k, self.p)

        # Compute e = H(r || m)
        e = self.hash_func(long_to_bytes(r) + long_to_bytes(m))

        # Compute s = (k + e * x) mod q
        s = (k + e * self.x) % self.q

        signature = (e, s)
        print(f"Signature: e = {e}, s = {s}\n")
        return signature

    def verify(self, message, signature):
        e, s = signature

        # Hash the message
        hash_obj = hashlib.sha256()
        hash_obj.update(message.encode('utf-8'))
        m = bytes_to_long(hash_obj.digest())

        # Compute r' = g^s * y^{-e} mod p
        y_inv = inverse(self.y, self.p)
        r_prime = (pow(self.g, s, self.p) * pow(y_inv, e, self.p)) % self.p

        # Compute e' = H(r' || m)
        e_prime = self.hash_func(long_to_bytes(r_prime) + long_to_bytes(m))

        print(f"Verification:\n Computed e': {e_prime}\n Provided e: {e}\n")

        return e_prime == e

    def hash_func(self, data):
        """
        Hash function using SHA-256. Returns an integer.
        """
        hash_obj = hashlib.sha256()
        hash_obj.update(data)
        return bytes_to_long(hash_obj.digest())


def main():
    # Initialize Schnorr Signature Scheme
    schnorr = SchnorrSignature(key_size=2048)

    # Alice signs a document
    message = "This is a confidential legal document."
    print(f"Original Message: {message}")
    signature = schnorr.sign(message)

    # Bob verifies the signature
    print("Verifying Signature...")
    is_valid = schnorr.verify(message, signature)
    print(f"Signature valid: {is_valid}\n")

    # Demonstrate signature verification failure (tampered message)
    tampered_message = "This is a tampered legal document."
    print(f"Tampered Message: {tampered_message}")
    print("Verifying Signature for Tampered Message...")
    is_valid_tampered = schnorr.verify(tampered_message, signature)
    print(f"Signature valid: {is_valid_tampered}\n")


if __name__ == "__main__":
    main()
