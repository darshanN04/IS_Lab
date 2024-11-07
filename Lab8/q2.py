import numpy as np
from collections import defaultdict
from sympy import isprime
import hashlib
import secrets
import math
# Paillier Cryptosystem Implementation with Hardcoded Primes
class Paillier:
    def __init__(self, p, q):
        if not (isprime(p) and isprime(q)):
            raise ValueError("Both p and q must be prime numbers.")
        self.p = p
        self.q = q
        self.n = self.p * self.q
        self.n_squared = self.n * self.n
        self.g = self.n + 1
        self.lambda_ = (self.p - 1) * (self.q - 1) // math.gcd(self.p - 1, self.q - 1)

    def encrypt(self, plaintext):
        r = secrets.randbelow(self.n - 1) + 1
        ciphertext = (pow(self.g, plaintext, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
        return int(ciphertext)  # Ensure it's a standard Python int

    def decrypt(self, ciphertext):
        u = (pow(ciphertext, self.lambda_, self.n_squared) - 1) % self.n_squared
        l = (u // self.n) % self.n
        plaintext = (l * pow(self.lambda_, -1, self.n)) % self.n
        return int(plaintext) 

# Step 2a: Create a dataset
documents = {
    1: "the quick brown fox jumps over the lazy dog",
    2: "never gonna give you up never gonna let you down",
    3: "hello world this is a test document",
    8: "the quick brown fox is clever",
}

# Step 2c: Create an inverted index
def create_inverted_index(docs):
    index = defaultdict(set)
    for doc_id, text in docs.items():
        words = text.split()
        for word in words:
            index[word].add(doc_id)
    return index

# Create the inverted index
inverted_index = create_inverted_index(documents)
print(inverted_index.items())
# Step 2b: Initialize Paillier with hardcoded primes
p = 17  # Example prime
q = 19  # Example prime
paillier = Paillier(p, q)

def string_to_int(s):
    return int(hashlib.sha256(s.encode()).hexdigest(), 16)

# Encrypt the inverted index
encrypted_index = {
    paillier.encrypt(string_to_int(word)): [paillier.encrypt(doc_id) for doc_id in doc_ids]
    for word, doc_ids in inverted_index.items()
}
encrypted_index1 = {
    paillier.decrypt(word): [paillier.decrypt(doc_id) for doc_id in doc_ids]
    for word, doc_ids in encrypted_index.items()
}

# Display the encrypted index for debugging
print("Encrypted Index:")
for word, encrypted_doc_ids in encrypted_index1.items():
    print(f"{word}: {[str(doc_id) for doc_id in encrypted_doc_ids]}")

# Step 2d: Implement the search function
def search(query):
    encrypted_query = paillier.encrypt(string_to_int(query))
    cc=paillier.decrypt(encrypted_query)
    results = {}
    print(encrypted_query,"jhuih")

    # Check the encrypted index for the encrypted query
    for word, encrypted_doc_ids in encrypted_index.items():
        ww=paillier.decrypt(word)
        if cc == ww:
            print("Success")
            for encrypted_doc_id in encrypted_doc_ids:
                doc_id = paillier.decrypt(encrypted_doc_id)
                print(doc_id)
                results[doc_id] = documents[doc_id]
            break

    return results

# Example search
query = "quick"
search_results = search(query)

# Output results
print("Search Results:")
if search_results:
    for doc_id, doc_text in search_results.items():
        print(f"Document ID {doc_id}: {doc_text}")
else:
    print("No documents found.")
doc_id_1 = paillier.encrypt(1)  # Random r generated
doc_id_2 = paillier.encrypt(1)  # Different random r generated
cc=paillier.encrypt(string_to_int(query))
print(paillier.decrypt(doc_id_1)," ",paillier.decrypt(cc))
print(doc_id_2)
print(doc_id_1)