# Exercise 3 - Brute-Force Attack on Reduced AES Key
# Harel Aronovich - 314860925
# Nikolay Savchenko - 323453076

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import time
import matplotlib.pyplot as plt


def expand_key(x, bits=20):
    """Convert a small integer to a 128-bit AES key by repeating the bit pattern"""
    bin_key = format(x, f'0{bits}b')  # convert number to bitstring
    repeated = (bin_key * 7)[:128]     # repeat and trim to 128 bits
    return int(repeated, 2).to_bytes(16, 'big')  # convert to 16-byte AES key


def encrypt_ecb(plaintext, key):
    """Encrypt using AES-ECB mode"""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def brute_force_attack(plaintext, target_ciphertext, key_bits):
    """Try all possible keys until we find the one that produces the target ciphertext"""
    key_space = 2 ** key_bits

    start_time = time.time()

    for x in range(key_space):
        key = expand_key(x, key_bits)
        ciphertext = encrypt_ecb(plaintext, key)

        if ciphertext == target_ciphertext:
            elapsed = time.time() - start_time
            return x, elapsed, x + 1  # found key, time, attempts

    # Should never reach here if target was created with valid key
    return None, time.time() - start_time, key_space


def main():
    print("=" * 60)
    print("Exercise 3: Brute-Force Attack on Reduced AES Key")
    print("=" * 60)
    print()

    # Known plaintext (exactly 16 bytes for AES block)
    plaintext = b"Hello student!!!"
    print(f"Plaintext: {plaintext}")
    print()

    # Key sizes to test
    key_sizes = [20, 22, 24]
    results = []

    for bits in key_sizes:
        print("-" * 40)
        print(f"Testing {bits}-bit key space (2^{bits} = {2**bits:,} keys)")
        print("-" * 40)

        # Pick a secret key at 75% of the key space for consistent results
        secret_key_value = int(0.75 * (2**bits))
        secret_key = expand_key(secret_key_value, bits)

        print(f"Secret key value: {secret_key_value}")
        print(f"Secret key (hex): {secret_key.hex()}")

        # Encrypt to get target ciphertext
        target_ciphertext = encrypt_ecb(plaintext, secret_key)
        print(f"Target ciphertext: {target_ciphertext.hex()}")
        print()

        # Brute-force attack
        print("Starting brute-force attack...")
        found_key, elapsed_time, attempts = brute_force_attack(plaintext, target_ciphertext, bits)

        if found_key is not None:
            print(f"Key FOUND: {found_key}")
            print(f"Attempts: {attempts:,}")
            print(f"Time: {elapsed_time:.2f} seconds")
            results.append((bits, elapsed_time))
        else:
            print("Key not found (error)")

        print()

    # Summary
    print("=" * 60)
    print("Summary of Results")
    print("=" * 60)
    print(f"{'Key Bits':<12} {'Key Space':<15} {'Time (sec)':<12}")
    print("-" * 40)
    for bits, elapsed in results:
        print(f"{bits:<12} {2**bits:<15,} {elapsed:<12.2f}")
    print()

    # Create plot
    print("Generating plot...")
    key_bits_list = [r[0] for r in results]
    times_list = [r[1] for r in results]

    plt.figure(figsize=(8, 6))
    plt.plot(key_bits_list, times_list, 'bo-', linewidth=2, markersize=10)
    plt.xlabel('Key Size (bits)', fontsize=12)
    plt.ylabel('Brute-Force Time (seconds)', fontsize=12)
    plt.title('AES Brute-Force Attack Time vs Key Size', fontsize=14)
    plt.xticks(key_bits_list)
    plt.grid(True, alpha=0.3)

    # Add data labels
    for bits, t in results:
        plt.annotate(f'{t:.2f}s', (bits, t), textcoords="offset points",
                    xytext=(0, 10), ha='center')

    plt.tight_layout()
    plt.savefig('brute_force_plot.png', dpi=150)
    print("Plot saved as 'brute_force_plot.png'")
    plt.show()

    print()
    print("=" * 60)
    print("Conclusion: Brute-force time grows exponentially with key size.")
    print("Each additional bit doubles the search space and time.")
    print("=" * 60)


if __name__ == "__main__":
    main()
