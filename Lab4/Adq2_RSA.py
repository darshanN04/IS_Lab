import math
from sympy import mod_inverse


# Function to factor a number n by trial division
def factorize_n(n):
    for i in range(2, math.isqrt(n) + 1):
        if n % i == 0:
            return i, n // i
    return None, None


# Function to simulate Eve's attack on the vulnerable RSA system
def attack_rsa(n, e):
    # Step 1: Factorize n to find p and q
    p, q = factorize_n(n)
    if not p or not q:
        print("Factorization failed.")
        return

    print(f"Found factors p = {p}, q = {q}")

    # Step 2: Compute phi(n) = (p-1) * (q-1)
    phi_n = (p - 1) * (q - 1)

    # Step 3: Compute the private key d as the modular inverse of e mod phi(n)
    try:
        d = mod_inverse(e, phi_n)
        print(f"Recovered private key d = {d}")
    except ValueError:
        print("Failed to compute modular inverse. Attack failed.")
        return

    # Simulating decryption of a ciphertext (for demonstration)
    # Assume some encrypted message (ciphertext) c is given
    c = 123456  # Example ciphertext
    decrypted_message = pow(c, d, n)
    print(f"Decrypted message: {decrypted_message}")


# Example vulnerable RSA parameters (small primes for demonstration)
p = 61
q = 53
n = p * q
e = 17  # Public exponent

# Start the attack
attack_rsa(n, e)
