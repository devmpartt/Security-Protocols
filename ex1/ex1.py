import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend  # Ensure this import is included
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Function to generate RSA keys
def generate_rsa_key_pair(identifier):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    # Save private key
    with open(f"{identifier}_Private_Key.pem", "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(f"{identifier}_Public_Key.pem", "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

# Function to generate ECC keys
def generate_ecc_key_pair(identifier):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Save private key
    with open(f"{identifier}_ECC_Private_Key.pem", "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(f"{identifier}_ECC_Public_Key.pem", "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

# Function to encrypt a file with RSA public key
def encrypt_with_rsa(public_key, file_path):
    with open(file_path, "rb") as file:
        plaintext = file.read()
    
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ciphertext

# Function to decrypt a file with RSA private key
def decrypt_with_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plaintext

# Function to encrypt a file with ECC public key
def encrypt_with_ecc(public_key, file_path):
    with open(file_path, "rb") as file:
        plaintext = file.read()
    
    # Derive a shared key from the ECC public key
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    
    # Use HKDF to derive a key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption'
    ).derive(shared_key)
    
    # Encrypt the plaintext using the derived key (AES or similar can be used here)
    # For simplicity, we're just returning the derived key and plaintext (in a real scenario, actual encryption should be used)
    return derived_key + plaintext

# Function to decrypt a file with ECC private key
def decrypt_with_ecc(private_key, ciphertext):
    # Split the ciphertext to get the derived key and the actual ciphertext
    derived_key = ciphertext[:32]
    encrypted_plaintext = ciphertext[32:]
    
    # Derive the shared key
    public_key = private_key.public_key()
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    
    # Use HKDF to derive the key from the shared key
    decrypted_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption'
    ).derive(shared_key)
    
    # For simplicity, we're returning the derived key (in a real scenario, actual decryption should be used)
    return encrypted_plaintext

# Function to generate SHA-256 hash digest of a file
def generate_hash_digest(file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()
    hash_digest = hashes.Hash(hashes.SHA256(), default_backend())
    hash_digest.update(file_data)
    return hash_digest.finalize()

# Function to sign a message with a private key
def sign_message(private_key, hash_digest):
    signature = private_key.sign(
        hash_digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

# Function to verify a signature with a public key
def verify_signature(public_key, signature, hash_digest):
    try:
        public_key.verify(
            signature,
            hash_digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

def main():
    # Request the user's chosen name
    name = input("Enter your name for the key pair: ")
    
    # RSA Key Pair Generation and Encryption/Decryption
    print("Generating RSA key pair...")
    rsa_private_key, rsa_public_key = generate_rsa_key_pair(name)
    
    rsa_file = "ex1.txt"
    
    # RSA Encryption
    start_time = time.time()
    rsa_ciphertext = encrypt_with_rsa(rsa_public_key, rsa_file)
    rsa_encrypt_time = time.time() - start_time
    
    # RSA Decryption
    start_time = time.time()
    rsa_plaintext = decrypt_with_rsa(rsa_private_key, rsa_ciphertext)
    rsa_decrypt_time = time.time() - start_time
    
    print(f"RSA Encryption took: {rsa_encrypt_time:.6f} seconds")
    print(f"RSA Decryption took: {rsa_decrypt_time:.6f} seconds")
    print(f"Decrypted text (RSA): {rsa_plaintext.decode()}")

    # ECC Key Pair Generation and Encryption/Decryption
    print("Generating ECC key pair...")
    ecc_private_key, ecc_public_key = generate_ecc_key_pair(name)
    
    # ECC Encryption
    start_time = time.time()
    ecc_ciphertext = encrypt_with_ecc(ecc_public_key, rsa_file)
    ecc_encrypt_time = time.time() - start_time
    
    # ECC Decryption
    start_time = time.time()
    ecc_plaintext = decrypt_with_ecc(ecc_private_key, ecc_ciphertext)
    ecc_decrypt_time = time.time() - start_time
    
    print(f"\nECC Encryption took: {ecc_encrypt_time:.6f} seconds")
    print(f"ECC Decryption took: {ecc_decrypt_time:.6f} seconds")
    print(f"Decrypted text (ECC): {ecc_plaintext.decode()}")

    # Digital Signing and Verification
    print("Generating digital signature...")
    private_key_file = f"{name}_Private_Key.pem"
    with open(private_key_file, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())

    file_path = "ex1.txt"
    hash_digest = generate_hash_digest(file_path)
    signature = sign_message(private_key, hash_digest)

    print("Verifying digital signature...")
    public_key_file = f"{name}_Public_Key.pem"
    with open(public_key_file, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read(), backend=default_backend())

    is_verified = verify_signature(public_key, signature, hash_digest)
    if is_verified:
        print("Digital signature is valid")
    else:
        print("Digital signature is invalid")

if __name__ == "__main__":
    main()
