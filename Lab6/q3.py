import hashlib
import time
import random
import string
from collections import defaultdict


# Function to generate random strings
def generate_random_strings(num_strings, min_length=10, max_length=20):
    random_strings = []
    for _ in range(num_strings):
        length = random.randint(min_length, max_length)
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        random_strings.append(random_string)
    return random_strings


# Function to hash a string using specified algorithm and measure computation time
def hash_string(algorithm, input_string):
    start_time = time.time()

    if algorithm == 'md5':
        hash_value = hashlib.md5(input_string.encode()).hexdigest()
    elif algorithm == 'sha1':
        hash_value = hashlib.sha1(input_string.encode()).hexdigest()
    elif algorithm == 'sha256':
        hash_value = hashlib.sha256(input_string.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hashing algorithm.")

    end_time = time.time()
    return hash_value, end_time - start_time


# Function to analyze performance and detect collisions
def analyze_hashing_performance(num_strings):
    random_strings = generate_random_strings(num_strings)
    hash_results = defaultdict(list)

    for algorithm in ['md5', 'sha1', 'sha256']:
        print(f"\nAnalyzing {algorithm.upper()} Hashing...")

        for input_string in random_strings:
            hash_value, elapsed_time = hash_string(algorithm, input_string)
            hash_results[algorithm].append((input_string, hash_value, elapsed_time))

        # Detect collisions
        collision_dict = defaultdict(list)
        for input_string, hash_value, _ in hash_results[algorithm]:
            collision_dict[hash_value].append(input_string)

        collisions = {hash_value: strings for hash_value, strings in collision_dict.items() if len(strings) > 1}

        # Print results
        total_time = sum(elapsed_time for _, _, elapsed_time in hash_results[algorithm])
        avg_time = total_time / num_strings

        print(f"Total strings hashed: {num_strings}")
        print(f"Average computation time: {avg_time:.6f} seconds")
        print(f"Number of collisions: {len(collisions)}")

        if collisions:
            print("Collisions found:")
            for hash_value, strings in collisions.items():
                print(f"  Hash: {hash_value} => Strings: {strings}")


# Running the analysis with 100 random strings
analyze_hashing_performance(num_strings=100)
