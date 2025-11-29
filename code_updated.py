import numpy as np # We use NumPy for matrix operations (multiplication, arrays) 

# Global parameters
N = 26  # Alphabet size (A-Z: 0-25)
a = 7   # First letter of Harel: H = 7
b = 13  # First letter of Niko: N = 13

class IterativeAttackFailure(Exception):
    #Raised when iterative attack cannot return plaintext
    pass

# ==================== Helper Functions ====================

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(a, m):
    #Calculate modular multiplicative inverse of a modulo m (26 in this case)
    gcd_val, x, y = extended_gcd(a % m, m)
    if gcd_val != 1:
        # Modular inverse doesn't exist
        return None
    return (x % m + m) % m

def matrix_determinant_mod(matrix, mod):
    """
    Calculate determinant of 2x2 matrix mod (26)
    """
    det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % mod
    return det

def matrix_inverse_mod26(matrix):
    #Calculate inverse of 2x2 matrix modulo 26
    det = matrix_determinant_mod(matrix, N)

    # Check if inverse exists Using numpy's gcd
    if np.gcd(det, N) != 1:
        raise ValueError(f"Matrix is not invertible")

    # Calculate modular inverse of determinant
    det_inv = mod_inverse(det, N)
    # Inverse = (d,-b; -c,a)
    inverse = np.array([
        [matrix[1][1], -matrix[0][1]],
        [-matrix[1][0], matrix[0][0]]
    ])

    # Multiply by determinant inverse and take mod 26
    inverse = (det_inv * inverse) % N # mod 26 

    return inverse.astype(int)

# ==================== Text Conversion Functions ====================

def text_to_numbers(text):
    #Convert text to list of numbers (A=0, B=1, ..., Z=25)
    #Ignores non-alphabetic characters
    text = text.upper()
    numbers = []
    for char in text:
        if char.isalpha():
            numbers.append(ord(char) - ord('A'))
    return numbers

def numbers_to_text(numbers):
    text = ""
    for num in numbers:
        text += chr((num % N) + ord('A'))
    return text

def string_to_matrix(key_string):
    #Convert 4-letter string to 2x2 matrix
    if len(key_string) != 4:
        raise ValueError("Key string must be exactly 4 characters")

    numbers = text_to_numbers(key_string)
    matrix = np.array([
        [numbers[0], numbers[1]],
        [numbers[2], numbers[3]]
    ])
    return matrix

# ==================== Key Validation ====================

def is_valid_key(matrix):
    """
    Verify that encryption key is valid
    Key is valid if gcd(det, 26) = 1
    This ensures the matrix is invertible mod 26
    """
    det = matrix_determinant_mod(matrix, N)
    gcd_val = np.gcd(det, N) 

    print(f"Matrix: {matrix[0].tolist()} {matrix[1].tolist()}, ", end="")
    print(f"det={det}, gcd={gcd_val}", end="")

    if gcd_val == 1:
        print(" -> Valid")
        return True
    else:
        print(" -> Invalid")
        return False

# Exercise 1
def NameCipher_encryption(plaintext, key):
    #Encrypt plaintext using NameCipher
    K1 = key['K1']
    K2 = key['K2']
    numbers = text_to_numbers(plaintext)

    # Padding if odd length
    if len(numbers) % 2 != 0:
        numbers.append(0)

    ciphertext_numbers = []
    shift_vector = np.array([a, b])

    for i in range(0, len(numbers), 2):
        block = np.array([numbers[i], numbers[i+1]])
        Y = (np.dot(block, K1) + shift_vector) % N
        Z = (np.dot(Y, K2) + shift_vector) % N
        ciphertext_numbers.extend(Z.tolist())

    return numbers_to_text(ciphertext_numbers)

def NameCipher_decryption(ciphertext, key):
    #Decrypt ciphertext using NameCipher

    K1 = key['K1']
    K2 = key['K2']
    # Calculate inverse matrices for keys
    K1_inv = matrix_inverse_mod26(K1)
    K2_inv = matrix_inverse_mod26(K2)

    numbers = text_to_numbers(ciphertext)

    plaintext_numbers = []
    shift_vector = np.array([a, b])

    # Process each 2-letter block
    for i in range(0, len(numbers), 2):
        block = np.array([numbers[i], numbers[i+1]])

        # Y = (Z - (a, b)) * K2^(-1)mod 26
        Y = np.dot((block - shift_vector), K2_inv) % N
        #X = (Y - (a, b)) * K1^(-1)mod 26
        X = np.dot((Y - shift_vector), K1_inv) % N

        plaintext_numbers.extend(X.tolist())
    return numbers_to_text(plaintext_numbers)

#Exercise 2: Iterative Attack 

def iterative_attack(ciphertext, key):
    print(f"Attempting iterative attack on: {ciphertext}")

    original = ciphertext
    current = ciphertext
    iterations = 0
    seen = set()

    while True:
        iterations += 1
        next_text = NameCipher_encryption(current, key)

        # Cycle found: returned to starting ciphertext
        if next_text == original:
            print(f"Cycle complete after {iterations} iterations")
            # The previous value is the plaintext
            return current, iterations

        # Infinite loop protection
        if next_text in seen:
            raise IterativeAttackFailure(
                f"Cycle detected but original ciphertext was never reached "
                f"(after {iterations} iterations)."
            )

        seen.add(next_text)
        current = next_text


# ==================== Main Execution and Examples ====================

def main():
    print(f"a = {a} (first letter of Harel: H)")
    print(f"b = {b} (first letter of Niko: N)")
    print(f"N = {N} (alphabet size)")

    # Define encryption keys
    K1 = np.array([ [17, 14], [ 0, 3] ])  # "ROAD"
    K2 = np.array([[3, 14], [14, 17] ])   # "DOOR"
    
    print("\n----Key Verification")
    print("Key K1 (from 'ROAD'):")
    is_valid_key(K1)
    print("\nKey K2 (from 'DOOR'):")
    is_valid_key(K2)
    
    print("\n----EXERCISE 1: Encryption")
    key = {'K1': K1, 'K2': K2}

    print("Encrypt 'HAREL'")
    plaintext1 = "HAREL"
    ciphertext1 = NameCipher_encryption(plaintext1, key)
    print(f"Plaintext:  {plaintext1}")
    print(f"Ciphertext: {ciphertext1}")

    print("\nEncrypt 'NIKO'")
    plaintext2 = "NIKO"
    ciphertext2 = NameCipher_encryption(plaintext2, key)
    print(f"Plaintext:  {plaintext2}")
    print(f"Ciphertext: {ciphertext2}")

    print("\nDecryption")
    print(f"Decrypt '{ciphertext1}' (ciphertext of HAREL)")
    # expect to get back original plaintext with padding
    decrypted1 = NameCipher_decryption(ciphertext1, key)
    print(f"Ciphertext:{ciphertext1}")
    print(f"Decrypted: {decrypted1}")
    print(f"Original:{plaintext1}")

    # expect to get back original plaintext with padding
    print(f"\nDecrypt '{ciphertext2}' (ciphertext of NIKO)")
    decrypted2 = NameCipher_decryption(ciphertext2, key)
    print(f"Ciphertext: {ciphertext2}")
    print(f"Decrypted: {decrypted2}")
    print(f"Original: {plaintext2}")

    print("\n----EXERCISE 2: Iterative Attack")
    print("decrypt by repeated encryption until cycle completes")
    #Attack on HAREL
    try:
        plaintext_found1, iterations1 = iterative_attack(ciphertext1, key)
        print(f"Plaintext: {plaintext_found1}")
        print(f"Original:  {plaintext1}")
        print(f"Match: {'YES' if plaintext_found1 == plaintext1+'A' else 'NO'}")
    except IterativeAttackFailure as e:
        print("\nIterative attack failed for HAREL:")
        print(e)

    print()
    #Attack on NIKO
    try:
        plaintext_found2, iterations2 = iterative_attack(ciphertext2, )
        print(f"Plaintext: {plaintext_found2}")
        print(f"Original:  {plaintext2}")
        print(f"Match: {'YES' if plaintext_found2 == plaintext2 else 'NO'}")
    except IterativeAttackFailure as e:
        print("\nIterative attack failed for NIKO:")
        print(e)

if __name__ == "__main__":
    main()