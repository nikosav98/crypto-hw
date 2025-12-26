# Exercise 2 - Avalanche Effect in AES
# Harel Aronovich - 314860925
# Nikolay Savchenko - 323453076

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import random

def encrypt_ecb(plaintext, key):
    #Encrypt using AES-ECB mode same as ex1
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def count_different_bits(bytes1, bytes2):
    #Count how many bits are different between two byte arrays - Hamming distance
    count = 0
    for b1, b2 in zip(bytes1, bytes2):
        # XOR the bytes and count the 1s (different bits), leetcode level easy
        xor_result = b1 ^ b2
        count += bin(xor_result).count('1')
    return count

def flip_bit(data, bit_position):
    #flip a single bit at the given position in the byte array
    # convert to list
    data_list = list(data)
    # find which byte and which bit within that byte
    byte_index = bit_position // 8
    bit_index = bit_position % 8
    # flip the bit using XOR
    data_list[byte_index] ^= (1 << bit_index)
    return bytes(data_list)


def main():
    # fixed 128-bit AES key (1)
     # set-up
    key = os.urandom(16)
    total_changed_bits = 0

    print("Exercise 2: Avalanche Effect in AES")
    print()
    print("Key (hex):", key.hex())
    print()
    print("Testing: flip 1 bit in plaintext and count changed bits in ciphertext")
    print()

    
    '''
    Perform the following experiment:
    1. Take a fixed 128-bit AES key.
    2. Encrypt two plaintexts that differ in exactly one bit.
    3. Compare the two ciphertexts and count how many output bits are different.
    4. Repeat this process 5 times with different random plaintexts.
    5. Display all results. How many output bits changed when a single input bit is flipped.
    This process is what we imlemented below
    '''

    for trial in range(1, 6):
        print(f"Trial {trial}:")

        # generate random 128-bit plaintext
        plaintext = os.urandom(16) #first plaintext
        # pick a bit to flip (we used a fixed sequence for reproducibility)
        bit_to_flip = trial + 5 
        #create modified plaintext with one bit flipped
        modified_plaintext = flip_bit(plaintext, bit_to_flip) #the modified plaintext
        #encrypt both
        ciphertext1 = encrypt_ecb(plaintext, key)
        ciphertext2 = encrypt_ecb(modified_plaintext, key)

        # Count different bits
        different_bits = count_different_bits(ciphertext1, ciphertext2)
        total_changed_bits += different_bits

        print(f"Original plaintext: {plaintext.hex()}")
        print(f"Modified plaintext: {modified_plaintext.hex()}")
        print(f"Bit flipped: position {bit_to_flip}") #expected bits 6,7,8,9,10
        print()
        print(f"Ciphertext 1: {ciphertext1.hex()}")
        print(f"Ciphertext 2: {ciphertext2.hex()}")
        print()
        print(f"Different bits in ciphertext: {different_bits} / 128")
        print()



    average = total_changed_bits / 5
    print(f"Average bits changed: {average:.1f} / 128 ({average/128*100:.1f}%)")

if __name__ == "__main__":
    main()