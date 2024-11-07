import random
import logging
from Crypto.Util import number
from datetime import datetime, timedelta

# Setup logging for auditing purposes
logging.basicConfig(filename='key_management.log', level=logging.INFO)

# Database simulation for hospitals/clinics
key_database = {}


# Rabin cryptosystem helper functions
def generate_large_prime(bits=1024):
    """Generate a large prime number."""
    return number.getPrime(bits)


def rabin_keygen(bits=1024):
    """Generate public and private keys using the Rabin cryptosystem."""
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    private_key = (p, q)
    public_key = n
    return public_key, private_key


def rabin_encrypt(public_key, message):
    """Encrypt a message using the Rabin cryptosystem."""
    n = public_key
    return pow(message, 2, n)


def rabin_decrypt(private_key, ciphertext):
    """Decrypt a ciphertext using the Rabin cryptosystem."""
    p, q = private_key
    n = p * q
    root_p = pow(ciphertext, (p + 1) // 4, p)
    root_q = pow(ciphertext, (q + 1) // 4, q)

    # Using the Chinese Remainder Theorem (CRT) to solve the system of congruences
    # x ≡ root_p (mod p)
    # x ≡ root_q (mod q)
    # Return both roots as Rabin has two possible decryption results
    return (root_p, root_q)


# KeyManager for key management operations
class KeyManager:
    def generate_key_pair(self, hospital_id, bits=1024):
        """Generate a new public and private key pair."""
        public_key, private_key = rabin_keygen(bits)
        key_database[hospital_id] = {
            'public_key': public_key,
            'private_key': private_key,
            'key_expiry': datetime.utcnow() + timedelta(days=365)  # 1 year expiry
        }
        logging.info(f"Generated new key pair for {hospital_id} at {datetime.utcnow()}")
        return public_key

    def revoke_key(self, hospital_id):
        """Revokes the key for a specific hospital or clinic."""
        if hospital_id in key_database:
            del key_database[hospital_id]
            logging.info(f"Revoked key for {hospital_id} at {datetime.utcnow()}")
        else:
            logging.warning(f"Key for {hospital_id} not found for revocation.")

    def renew_key(self, hospital_id):
        """Renews the key for a specific hospital or clinic."""
        if hospital_id in key_database:
            public_key, private_key = rabin_keygen()
            key_database[hospital_id] = {
                'public_key': public_key,
                'private_key': private_key,
                'key_expiry': datetime.utcnow() + timedelta(days=365)
            }
            logging.info(f"Renewed key pair for {hospital_id} at {datetime.utcnow()}")
        else:
            logging.warning(f"Key for {hospital_id} not found for renewal.")

    def check_key_expiry(self, hospital_id):
        """Check if the key is expired for a hospital and renew it if necessary."""
        if hospital_id in key_database:
            key_info = key_database[hospital_id]
            if key_info['key_expiry'] < datetime.utcnow():
                self.renew_key(hospital_id)
            return key_info['public_key']
        return None


# KeyManager instance
key_manager = KeyManager()


# Command-line interface (CLI) simulation for key management
def generate_key_cli():
    hospital_id = input("Enter hospital ID to generate key pair: ")
    if hospital_id:
        public_key = key_manager.generate_key_pair(hospital_id)
        print(f"Generated public key for {hospital_id}: {public_key}")
    else:
        print("Hospital ID is required.")


def revoke_key_cli():
    hospital_id = input("Enter hospital ID to revoke key: ")
    if hospital_id:
        key_manager.revoke_key(hospital_id)
        print(f"Key for {hospital_id} has been revoked.")
    else:
        print("Hospital ID is required.")


def renew_key_cli():
    hospital_id = input("Enter hospital ID to renew key: ")
    if hospital_id:
        key_manager.renew_key(hospital_id)
        print(f"Key for {hospital_id} has been renewed.")
    else:
        print("Hospital ID is required.")


def check_key_expiry_cli():
    hospital_id = input("Enter hospital ID to check key expiry: ")
    if hospital_id:
        public_key = key_manager.check_key_expiry(hospital_id)
        if public_key:
            print(f"Public key for {hospital_id}: {public_key}")
        else:
            print(f"No key found for {hospital_id} or key is expired.")
    else:
        print("Hospital ID is required.")


def decrypt_data_cli():
    hospital_id = input("Enter hospital ID for decryption: ")
    ciphertext = int(input("Enter ciphertext (numeric): "))

    if hospital_id and ciphertext:
        public_key = key_manager.check_key_expiry(hospital_id)
        if public_key:
            # Decrypt the ciphertext using Rabin Decryption
            decrypted_data = rabin_decrypt(key_database[hospital_id]['private_key'], ciphertext)
            print(f"Decrypted data for {hospital_id}: {decrypted_data}")
        else:
            print(f"Key for {hospital_id} not found or expired.")
    else:
        print("Hospital ID and ciphertext are required.")


def main():
    while True:
        print("\n---- Key Management CLI ----")
        print("1. Generate Key Pair")
        print("2. Revoke Key")
        print("3. Renew Key")
        print("4. Check Key Expiry")
        print("5. Decrypt Data")
        print("6. Exit")

        choice = input("Enter choice: ")

        if choice == '1':
            generate_key_cli()
        elif choice == '2':
            revoke_key_cli()
        elif choice == '3':
            renew_key_cli()
        elif choice == '4':
            check_key_expiry_cli()
        elif choice == '5':
            decrypt_data_cli()
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
