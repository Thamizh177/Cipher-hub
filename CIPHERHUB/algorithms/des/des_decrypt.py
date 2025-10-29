from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import binascii

def unpad_text(padded_text):
    """
    Remove the padding from the decrypted text
    """
    padding_length = padded_text[-1]
    if padding_length > 8:
        # Invalid padding, return as is
        return padded_text
    
    # Check if the padding is valid (all padding bytes should be the same)
    if padded_text[-padding_length:] != bytes([padding_length]) * padding_length:
        # Invalid padding, return as is
        return padded_text
    
    return padded_text[:-padding_length]

def decrypt_text(ciphertext_b64, iv_b64, key_hex):
    """
    Decrypt text using DES in CBC mode
    """
    # Convert the key, IV, and ciphertext from their base64/hex representations
    try:
        key = binascii.unhexlify(key_hex)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
    except (binascii.Error, base64.Error) as e:
        return f"Error decoding input: {str(e)}"
    
    # Create the cipher object
    cipher = Cipher(
        algorithms.TripleDES(key),  # Using TripleDES for better security
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Create the decryptor
    decryptor = cipher.decryptor()
    
    try:
        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove the padding
        plaintext = unpad_text(padded_plaintext)
        
        # Try to decode the plaintext as UTF-8
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            # If we can't decode as UTF-8, return the binary data
            return plaintext
    except Exception as e:
        return f"Decryption error: {str(e)}"

def decrypt_file(encrypted_file_path, output_path, key_hex):
    """
    Decrypt a file using DES in CBC mode
    """
    # Convert the key from hex representation
    try:
        key = binascii.unhexlify(key_hex)
    except binascii.Error as e:
        return f"Error decoding key: {str(e)}"
    
    # Read the encrypted file
    try:
        with open(encrypted_file_path, 'rb') as f:
            data = f.read()
            
        # The first 8 bytes are the IV, the rest is the ciphertext
        if len(data) < 8:
            return "Encrypted file is too small"
        
        iv = data[:8]
        ciphertext = data[8:]
    except Exception as e:
        return f"Error reading encrypted file: {str(e)}"
    
    # Create the cipher object
    cipher = Cipher(
        algorithms.TripleDES(key),  # Using TripleDES for better security
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Create the decryptor
    decryptor = cipher.decryptor()
    
    try:
        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove the padding
        plaintext = unpad_text(padded_plaintext)
        
        # Write the plaintext to the output file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return f"File successfully decrypted to {output_path}"
    except Exception as e:
        return f"Decryption error: {str(e)}"