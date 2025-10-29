import numpy as np

def mod_inverse(a, m):
    """Find the modular inverse of a under modulo m."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"Modular inverse does not exist for determinant {a} under modulo {m}.")

def matrix_mod_inverse(matrix, modulus):
    """Calculate the modular inverse of a matrix under a given modulus."""
    det = int(np.round(np.linalg.det(matrix)))  # Determinant of the matrix
    det_mod = det % modulus  # Determinant mod 26
    try:
        det_inv = mod_inverse(det_mod, modulus)  # Modular inverse of determinant
    except ValueError:
        raise ValueError(f"Key matrix determinant {det} is not invertible under modulo {modulus}.")
    
    # Calculate the adjugate matrix (transpose of cofactor matrix)
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    matrix_mod_inv = (det_inv * adjugate) % modulus
    return matrix_mod_inv

def hill_cipher_decrypt(ciphertext, key_matrix=None):
    """Decrypt the ciphertext using the Hill Cipher algorithm."""
    ciphertext = ciphertext.upper()

    # If key matrix is provided, use it; otherwise, default to a random 3x3 matrix
    if key_matrix is None:
        key_matrix = generate_random_key_matrix()  # Default to 3x3 matrix if not provided
    else:
        key_values = [int(x) for x in key_matrix.split(",")]
        matrix_size = int(len(key_values) ** 0.5)
        if matrix_size * matrix_size != len(key_values):
            raise ValueError("Key matrix must be a square matrix.")
        key_matrix = np.array(key_values).reshape(matrix_size, matrix_size)

    # Compute inverse of the key matrix modulo 26
    key_matrix_inv = matrix_mod_inverse(key_matrix, 26)

    ciphertext_vector = [ord(char) - 65 for char in ciphertext]
    decrypted_text = ""
    for i in range(0, len(ciphertext_vector), key_matrix.shape[0]):
        chunk = ciphertext_vector[i:i + key_matrix.shape[0]]
        # Ensure chunk length matches matrix size by padding with 'X'
        if len(chunk) < key_matrix.shape[0]:
            chunk += [23] * (key_matrix.shape[0] - len(chunk))  # ASCII 'X' = 23
        decrypted_chunk = np.dot(key_matrix_inv, chunk) % 26
        decrypted_text += ''.join(chr(int(num) + 65) for num in decrypted_chunk)
    
    return decrypted_text
