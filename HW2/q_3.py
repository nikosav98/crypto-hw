# Exercise 3 - Brute-Force Attack on Reduced AES Key
# Harel Aronovich - 314860925
# Nikolay Savchenko - 323453076

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import time
import matplotlib.pyplot as plt


def expand_key(x, bits=20):
    #Convert a small integer to a 128-bit AES key by repeating the bit pattern
    bin_key = format(x, f'0{bits}b')  # convert number to bitstring
    repeated = (bin_key * 7)[:128]     # repeat and trim to 128 bits
    return int(repeated, 2).to_bytes(16, 'big')  # convert to 16-byte AES key


def encrypt_ecb(plaintext, key):
    #Encrypt using AES-ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def brute_force_attack(plaintext, target_ciphertext, key_bits):
    #try all possible keys until we find the one that produces the target ciphertext
    key_space = 2 ** key_bits #2^key_bits possible keys
    start_time = time.time() #start timer

    for x in range(key_space):
        key = expand_key(x, key_bits)
        ciphertext = encrypt_ecb(plaintext, key)

        if ciphertext == target_ciphertext: #key found
            elapsed = time.time() - start_time
            return x, elapsed, x  # found key, time, attempts

    #if this was reached, key was not found - sHould not happen in this controlled scenario
    return None, time.time() - start_time, key_space


def main():
    print("Exercise 3: Brute-Force Attack on Reduced AES Key")
    print()

    # known plaintext (exactly 16 bytes for AES block)
    plaintext = b"Hello Teacher!!!"
    print(f"Plaintext: Hello Teacher!!!")
    print()

    key_sizes = [20,22,24]
    results = []

    for bits in key_sizes:
        print(f"Testing {bits} with bit key space (2^{bits} = {2**bits:,} keys)")

        #here we chose a secret key to demonstrate worst case almost revery time
        # to keep the running time reasonable for demonstration
        secret_key_value = int(0.75 * (2**bits))
        secret_key = expand_key(secret_key_value, bits)

        print(f"Secret key value: {secret_key_value}")
        print(f"Secret key (hex): {secret_key.hex()}")

        # Encrypt to get target ciphertext
        target_ciphertext = encrypt_ecb(plaintext, secret_key)
        print(f"Target ciphertext: {target_ciphertext.hex()}")
        print()

        # Brute-force attack
        print("starting brute force attack...")
        found_key, elapsed_time, attempts = brute_force_attack(plaintext, target_ciphertext, bits)

        if found_key is not None:
            print(f"Key FOUND: {found_key}")
            print(f"Attempts: {attempts:,}")
            print(f"Time: {elapsed_time:.2f} seconds")
            results.append((bits, elapsed_time))
        else:
            print("Key not found (error), shouldnt happen in this controlled scenario")
        print() #space


    print("Summary of Results")
    print(f"{'Key Bits':<12} {'Key Space':<15} {'Time (sec)':<12}")
    for bits, elapsed in results:
        print(f"{bits:<12} {2**bits:<15,} {elapsed:<12.2f}")
    print()

    #plot generation
    # create plot
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
        plt.annotate(f'{t:.2f}s', (bits, t), textcoords="offset points", xytext=(0, 10), ha='center')

    plt.tight_layout()
    plt.savefig('brute_force_plot.png', dpi=150)
    print("Plot saved as 'brute_force_plot.png'")
    plt.show()
    print()
    print("Each additional bit doubles the search space and time")


if __name__ == "__main__":
    main()