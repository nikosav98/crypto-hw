# Exercise 1 - AES Encryption using ECB and CBC modes
# Harel Aronovich - 314860925
# Nikolay Savchenko - 323453076

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

#pad unpad
def pad_message(message_bytes):
    #add PKCS7 padding to make message a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    return padder.update(message_bytes) + padder.finalize()

'''
reads last byte
interprets it as padding length
verifies padding is consistent
removes padding
returns original plaintext
'''
def unpad_message(padded_bytes):
    #Remove PKCS7 padding from message
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_bytes) + unpadder.finalize()

#encrypt decrypt functions
def encrypt_ecb(plaintext, key):
    #Encrypt using AES-ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB()) #use aes algorithm with ECB mode
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_ecb(ciphertext, key):
    #decrypt using AES-ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_cbc(plaintext, key, iv):
    #encrypt using AES-CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_cbc(ciphertext, key, iv):
    #decrypt using AES-CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def main():
    # the message we need to encrypt
    message = "Homework 2 for the Course Cryptology: Harel Aronovich, 314860925 and Nikolay Savchenko, 323453076."
    plaintext = message.encode('utf-8') # crypto libraries expect bytes not Python str so this is necessary

    # generate random key and IV
    key = os.urandom(16)  # AES-128
    iv = os.urandom(16)

    padded_data = pad_message(plaintext)# Pad the message

    print("Q1: AES encryption/decryption")
    print()
    print("Original Message:")
    print(message)
    print()
    print("Key (hex):", key.hex())
    print()

    # ECB Mode
    print("ECB Mode")
    ciphertext_ecb = encrypt_ecb(padded_data, key) # main encryption function
    print("Ciphertext (hex):")
    print(ciphertext_ecb.hex())
    print()
    decrypted_ecb = unpad_message(decrypt_ecb(ciphertext_ecb, key))
    print("Decrypted Message:")
    print(decrypted_ecb.decode('utf-8'))
    print()

    # CBC Mode
    print("CBC Mode")
    print("IV (hex):", iv.hex())
    print()
    ciphertext_cbc = encrypt_cbc(padded_data, key, iv) # iv is needed for CBC mode!!!
    print("Ciphertext (hex):")
    print(ciphertext_cbc.hex())
    print()
    decrypted_cbc = unpad_message(decrypt_cbc(ciphertext_cbc, key, iv))
    print("Decrypted Message:")
    print(decrypted_cbc.decode('utf-8')) # decode bytes back to str
    print()

if __name__ == "__main__":
    main()