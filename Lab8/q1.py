from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from collections import defaultdict


# AES encryption key (must be 16, 24, or 32 bytes long)
key = get_random_bytes(16)  # 16 bytes key for AES-128

# Sample text corpus with 10 documents
documents = [
    "The quick brown fox jumps over the lazy dog",
    "Never jump over the lazy dog quickly",
    "A quick brown fox is faster than a slow dog",
    "Dogs are loyal and friendly animals",
    "Foxes are quick and clever animals",
    "The fox is clever and the dog is lazy",
    "The dog chases the fox around the park",
    "A quick fox is a better hunter than a dog",
    "Animals like dogs and foxes are very intelligent",
    "The brown fox jumped over the lazy dog again"
]

# AES encryption function
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ciphertext = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ciphertext

# AES decryption function
def decrypt_data(iv, ciphertext, key):
    iv = base64.b64decode(iv)
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    return pt

# Function to build inverted index
def build_inverted_index(documents):
    inverted_index = defaultdict(list)
    for doc_id, doc in enumerate(documents):
        words = set(doc.lower().split())  # Convert to lower case and split into words
        for word in words:
            inverted_index[word].append(doc_id)
    return inverted_index

# Function to search the inverted index (encrypted)
def search_query(query, encrypted_index, key):
    encrypted_query = encrypt_data(query, key)
    encrypted_docs = []

    # Iterate through each word in the query
    for word in query.split():
        word = word.lower()  # Lowercase the query word
        if word in encrypted_index:
            # For each word in the inverted index, add the encrypted document IDs
            encrypted_docs.extend(encrypted_index[word])

    # Decrypt the document IDs and display the corresponding documents
    decrypted_docs = []
    for encrypted_doc in encrypted_docs:
        iv, encrypted_doc_id = encrypted_doc
        decrypted_doc_id = decrypt_data(iv, encrypted_doc_id, key)  # Decrypt doc_id
        decrypted_docs.append(documents[int(decrypted_doc_id)])  # Get the document based on the decrypted doc_id

    return decrypted_docs


# Build the inverted index
inverted_index = build_inverted_index(documents)

# Encrypt the inverted index
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    # Encrypt the document IDs associated with the word
    encrypted_doc_ids = []
    for doc_id in doc_ids:
        iv, encrypted_doc_id = encrypt_data(str(doc_id), key)
        encrypted_doc_ids.append((iv, encrypted_doc_id))
    encrypted_index[word] = encrypted_doc_ids

# Example: Perform a search query
query = "quick fox"
decrypted_docs = search_query(query, encrypted_index, key)

# Display the documents
print(f"Search Results for Query: {query}")
for doc in decrypted_docs:
    print(doc)
