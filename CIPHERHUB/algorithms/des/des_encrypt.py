import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import binascii

def pad_text(text):
    """
    Pad the text to be a multiple of 8 bytes (DES block size)
    """
    padding_length = 8 - (len(text) % 8)
    padding = bytes([padding_length]) * padding_length
    return text + padding

def generate_key():
    """
    Generate a random 8-byte (64-bit) key for DES
    """
    return os.urandom(8)

def encrypt_text(plaintext, key=None):
    """
    Encrypt text using DES in CBC mode with a random IV
    """
    if key is None:
        key = generate_key()
    elif isinstance(key, str):
        # Convert hex string to bytes
        try:
            key = binascii.unhexlify(key)
        except binascii.Error:
            # If not hex, use as UTF-8
            key = key.encode('utf-8')
            # Ensure key is 8 bytes (padding or truncating)
            if len(key) < 8:
                key = key.ljust(8, b'\0')
            elif len(key) > 8:
                key = key[:8]
    
    # Generate a random IV
    iv = os.urandom(8)
    
    # Prepare the plaintext
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Pad the plaintext to a multiple of 8 bytes
    padded_plaintext = pad_text(plaintext)
    
    # Create the cipher object
    cipher = Cipher(
        algorithms.TripleDES(key),  # Using TripleDES for better security
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Create the encryptor
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Return the IV and ciphertext as base64 encoded strings
    return {
        'key': binascii.hexlify(key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

def encrypt_file(file_path, output_path=None, key=None):
    """
    Encrypt a file using DES in CBC mode with a random IV
    """
    if output_path is None:
        output_path = file_path + '.enc'
    
    # Generate key if not provided
    if key is None:
        key = generate_key()
    elif isinstance(key, str):
        # Convert hex string to bytes
        try:
            key = binascii.unhexlify(key)
        except binascii.Error:
            # If not hex, use as UTF-8
            key = key.encode('utf-8')
            # Ensure key is 8 bytes (padding or truncating)
            if len(key) < 8:
                key = key.ljust(8, b'\0')
            elif len(key) > 8:
                key = key[:8]
    
    # Generate a random IV
    iv = os.urandom(8)
    
    # Create the cipher object
    cipher = Cipher(
        algorithms.TripleDES(key),  # Using TripleDES for better security
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Create the encryptor
    encryptor = cipher.encryptor()
    
    # Read the file in binary mode
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    # Pad the plaintext to a multiple of 8 bytes
    padded_plaintext = pad_text(plaintext)
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Write the IV and ciphertext to the output file
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)
    
    return {
        'key': binascii.hexlify(key).decode('utf-8'),
        'output_file': output_path
    }