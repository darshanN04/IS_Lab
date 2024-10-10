def custom_hash(input_string):
    """
    Computes a 32-bit hash for the given input string using a custom algorithm.

    The algorithm:
    1. Initializes the hash value to 5381.
    2. For each character in the input string:
        a. Multiplies the current hash by 33.
        b. Adds the ASCII value of the character.
        c. Applies bitwise XOR with the hash shifted right by 16 bits.
        d. Rotates the hash left by 13 bits to ensure thorough mixing.
    3. Masks the final hash to keep it within a 32-bit range.

    Args:
        input_string (str): The string to hash.

    Returns:
        int: The resulting 32-bit hash value.
    """
    hash_value = 5381  # Initial hash value

    for char in input_string:
        # Step 2a: Multiply current hash by 33 and add ASCII value
        hash_value = (hash_value * 33) + ord(char)

        # Step 2c: Apply bitwise XOR with hash shifted right by 16 bits
        hash_value ^= (hash_value >> 16)

        # Step 2d: Rotate left by 13 bits and mask to keep it within 32 bits
        hash_value = ((hash_value << 13) | (hash_value >> (32 - 13))) & 0xFFFFFFFF

    # Step 3: Ensure the final hash is within 32 bits
    hash_value &= 0xFFFFFFFF

    return hash_value

# Example usage
if __name__ == "__main__":
    test_strings = [
        "Hello, World!",
        "OpenAI",
        "ChatGPT",
        "The quick brown fox jumps over the lazy dog",
        "",
        "1234567890",
        "!@#$%^&*()_+-=[]{}|;':\",./<>?",
        "こんにちは世界"  # "Hello, World!" in Japanese
    ]

    for s in test_strings:
        hash_val = custom_hash(s)
        print(f"Input String: '{s}' -> Hash Value: {hash_val}")
