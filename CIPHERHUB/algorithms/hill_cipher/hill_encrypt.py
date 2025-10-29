import numpy as np
import random
import math

# Function to generate a random invertible matrix
def generate_random_key_matrix(matrix_size=3):
    while True:
        matrix_values = [random.randint(0, 25) for _ in range(matrix_size * matrix_size)]
        matrix = np.array(matrix_values).reshape(matrix_size, matrix_size)
        
        # Check if the matrix is invertible
        det = int(np.round(np.linalg.det(matrix))) % 26
        if det != 0 and np.gcd(det, 26) == 1:  # Matrix is invertible
            return matrix

# Function to encrypt the plaintext using Hill Cipher
def hill_cipher_encrypt(plaintext, key_matrix_str=None):
    # If a key matrix is provided, use it; otherwise, generate a random 3x3 matrix
    if key_matrix_str:
        key_matrix = np.array([list(map(int, key_matrix_str.split(',')))]).reshape(int(math.sqrt(len(key_matrix_str.split(',')))), -1)
    else:
        key_matrix = generate_random_key_matrix()  # Default to 3x3 matrix if not provided
    
    # Remove spaces from the plaintext and convert to uppercase
    plaintext = plaintext.replace(" ", "").upper()

    # Ensure the plaintext length is a multiple of the matrix size
    while len(plaintext) % key_matrix.shape[0] != 0:
        plaintext += "X"  # Pad with 'X' if needed

    # Convert plaintext to numeric form (A=0, B=1, ..., Z=25)
    plaintext_numeric = [ord(char) - 65 for char in plaintext]

    # Reshape the plaintext into a matrix
    plaintext_matrix = np.array(plaintext_numeric).reshape(-1, key_matrix.shape[0]).T

    # Encrypt the plaintext
    encrypted_matrix = np.dot(key_matrix, plaintext_matrix) % 26

    # Convert the encrypted matrix back to letters
    encrypted_text = ''.join(chr(num + 65) for num in encrypted_matrix.T.flatten())

    # Return the encrypted text and the key matrix
    return encrypted_text, key_matrix
