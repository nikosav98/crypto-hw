# Exercise 2 - Avalanche Effect in AES
# Harel Aronovich - 314860925
# Nikolay Savchenko - 323453076

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import random


def encrypt_ecb(plaintext, key):
    """Encrypt using AES-ECB mode"""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def count_different_bits(bytes1, bytes2):
    """Count how many bits are different between two byte arrays (Hamming distance)"""
    count = 0
    for b1, b2 in zip(bytes1, bytes2):
        # XOR the bytes and count the 1s (different bits)
        xor_result = b1 ^ b2
        count += bin(xor_result).count('1')
    return count


def flip_bit(data, bit_position):
    """Flip a single bit at the given position in the byte array"""
    # Convert to list so we can modify it
    data_list = list(data)

    # Find which byte and which bit within that byte
    byte_index = bit_position // 8
    bit_index = bit_position % 8

    # Flip the bit using XOR
    data_list[byte_index] ^= (1 << bit_index)

    return bytes(data_list)


def main():
    # Fixed 128-bit AES key
    key = os.urandom(16)

    print("=" * 60)
    print("Exercise 2: Avalanche Effect in AES")
    print("=" * 60)
    print()
    print("Key (hex):", key.hex())
    print()
    print("Testing: Flip 1 bit in plaintext, count changed bits in ciphertext")
    print("Expected: ~64 bits (50% of 128 bits) should change")
    print()

    total_changed_bits = 0

    for trial in range(1, 6):
        print("-" * 40)
        print(f"Trial {trial}")
        print("-" * 40)

        # Generate random 128-bit plaintext
        plaintext = os.urandom(16)

        # Pick a random bit to flip (0 to 127)
        bit_to_flip = random.randint(0, 127)

        # Create modified plaintext with one bit flipped
        modified_plaintext = flip_bit(plaintext, bit_to_flip)

        # Encrypt both
        ciphertext1 = encrypt_ecb(plaintext, key)
        ciphertext2 = encrypt_ecb(modified_plaintext, key)

        # Count different bits
        different_bits = count_different_bits(ciphertext1, ciphertext2)
        total_changed_bits += different_bits

        print(f"Original plaintext:  {plaintext.hex()}")
        print(f"Modified plaintext:  {modified_plaintext.hex()}")
        print(f"Bit flipped: position {bit_to_flip}")
        print()
        print(f"Ciphertext 1: {ciphertext1.hex()}")
        print(f"Ciphertext 2: {ciphertext2.hex()}")
        print()
        print(f"Different bits in ciphertext: {different_bits} / 128")
        print()

    # Summary
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    average = total_changed_bits / 5
    print(f"Average bits changed: {average:.1f} / 128 ({average/128*100:.1f}%)")
    print()
    print("Conclusion: AES shows good avalanche effect -")
    print("flipping 1 input bit changes ~50% of output bits.")
    print("=" * 60)


if __name__ == "__main__":
    main()
