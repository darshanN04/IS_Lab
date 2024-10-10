import hashlib
import random
import string
import time
from collections import defaultdict


def generate_random_strings(num_strings=100, min_length=20, max_length=100):
    """
    Generates a list of random strings.

    Args:
        num_strings (int): Number of random strings to generate.
        min_length (int): Minimum length of each string.
        max_length (int): Maximum length of each string.

    Returns:
        List[str]: A list containing the generated random strings.
    """
    random_strings = []
    for _ in range(num_strings):
        length = random.randint(min_length, max_length)
        # Generate a random string of specified length
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
        random_strings.append(rand_str)
    return random_strings


def compute_hashes(strings, hash_func):
    """
    Computes the hash values for a list of strings using the specified hashing function.

    Args:
        strings (List[str]): The list of strings to hash.
        hash_func (str): The name of the hashing function ('md5', 'sha1', 'sha256').

    Returns:
        Tuple[List[str], float]: A tuple containing the list of hash values and the time taken to compute them.
    """
    hashes = []
    start_time = time.perf_counter()

    for s in strings:
        # Encode the string to bytes
        encoded_str = s.encode('utf-8')
        # Compute the hash using the specified hash function
        if hash_func.lower() == 'md5':
            hash_obj = hashlib.md5(encoded_str)
        elif hash_func.lower() == 'sha1':
            hash_obj = hashlib.sha1(encoded_str)
        elif hash_func.lower() == 'sha256':
            hash_obj = hashlib.sha256(encoded_str)
        else:
            raise ValueError("Unsupported hash function. Choose from 'md5', 'sha1', 'sha256'.")

        # Append the hexadecimal digest to the list
        hashes.append(hash_obj.hexdigest())

    end_time = time.perf_counter()
    computation_time = end_time - start_time
    return hashes, computation_time


def detect_collisions(hashes):
    """
    Detects collisions in a list of hash values.

    Args:
        hashes (List[str]): The list of hash values.

    Returns:
        List[Tuple[int, int, str]]: A list of tuples containing indices of colliding strings and the hash value.
    """
    hash_map = defaultdict(list)
    collisions = []

    for index, hash_val in enumerate(hashes):
        hash_map[hash_val].append(index)

    for hash_val, indices in hash_map.items():
        if len(indices) > 1:
            # Record all pairs of collisions
            for i in range(len(indices)):
                for j in range(i + 1, len(indices)):
                    collisions.append((indices[i], indices[j], hash_val))

    return collisions


def main():
    # Step 1: Generate a dataset of random strings
    num_strings = 100  # You can vary this between 50 to 100 as needed
    random_strings = generate_random_strings(num_strings=num_strings)
    print(f"Generated {num_strings} random strings.\n")

    # Define the hashing algorithms to test
    hashing_algorithms = ['md5', 'sha1', 'sha256']

    # Dictionary to store results
    results = {}

    # Step 2: Compute hashes and measure computation time
    for algo in hashing_algorithms:
        hashes, comp_time = compute_hashes(random_strings, algo)
        results[algo] = {
            'hashes': hashes,
            'time': comp_time
        }
        print(f"Computed {algo.upper()} hashes in {comp_time:.6f} seconds.")

    print("\nCollision Detection Results:")

    # Step 3: Detect collisions for each hashing algorithm
    for algo in hashing_algorithms:
        hashes = results[algo]['hashes']
        collisions = detect_collisions(hashes)
        if collisions:
            print(f"\nCollisions found in {algo.upper()}:")
            for coll in collisions:
                index1, index2, hash_val = coll
                print(f" - String {index1} and String {index2} have the same hash: {hash_val}")
        else:
            print(f" - No collisions detected in {algo.upper()} hashes.")

    # Optional: Detailed Summary
    print("\nSummary:")
    for algo in hashing_algorithms:
        comp_time = results[algo]['time']
        hashes = results[algo]['hashes']
        collisions = detect_collisions(hashes)
        num_collisions = len(collisions)
        print(f"{algo.upper()}:")
        print(f"  Computation Time: {comp_time:.6f} seconds")
        print(f"  Number of Collisions: {num_collisions}")


if __name__ == "__main__":
    main()
