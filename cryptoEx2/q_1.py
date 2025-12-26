# Exercise 1 - AES Encryption using ECB and CBC modes
# Harel Aronovich - 314860925
# Nikolay Savchenko - 323453076

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def pad_message(message_bytes):
    """Add PKCS7 padding to make message a multiple of 16 bytes"""
    padder = padding.PKCS7(128).padder()
    return padder.update(message_bytes) + padder.finalize()


def unpad_message(padded_bytes):
    """Remove PKCS7 padding from message"""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_bytes) + unpadder.finalize()


def encrypt_ecb(plaintext, key):
    """Encrypt using AES-ECB mode"""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_ecb(ciphertext, key):
    """Decrypt using AES-ECB mode"""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_cbc(plaintext, key, iv):
    """Encrypt using AES-CBC mode"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_cbc(ciphertext, key, iv):
    """Decrypt using AES-CBC mode"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def main():
    # The message we need to encrypt
    message = "Homework 2 for the Course Cryptology: Harel Aronovich, 314860925 and Nikolay Savchenko, 323453076."
    plaintext = message.encode('utf-8')

    # Generate random key and IV
    key = os.urandom(16)  # AES-128
    iv = os.urandom(16)

    # Pad the message
    padded_data = pad_message(plaintext)

    print("=" * 60)
    print("Exercise 1: AES Encryption/Decryption")
    print("=" * 60)
    print()
    print("Original Message:")
    print(message)
    print()
    print("Key (hex):", key.hex())
    print()

    # ECB Mode
    print("-" * 40)
    print("ECB Mode")
    print("-" * 40)

    ciphertext_ecb = encrypt_ecb(padded_data, key)
    print("Ciphertext (hex):")
    print(ciphertext_ecb.hex())
    print()

    decrypted_ecb = unpad_message(decrypt_ecb(ciphertext_ecb, key))
    print("Decrypted Message:")
    print(decrypted_ecb.decode('utf-8'))
    print()

    # CBC Mode
    print("-" * 40)
    print("CBC Mode")
    print("-" * 40)
    print("IV (hex):", iv.hex())
    print()

    ciphertext_cbc = encrypt_cbc(padded_data, key, iv)
    print("Ciphertext (hex):")
    print(ciphertext_cbc.hex())
    print()

    decrypted_cbc = unpad_message(decrypt_cbc(ciphertext_cbc, key, iv))
    print("Decrypted Message:")
    print(decrypted_cbc.decode('utf-8'))
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
