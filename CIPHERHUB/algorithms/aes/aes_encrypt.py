# algorithms/aes/aes_encrypt.py
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

def generate_key():
    """Generate a random 256-bit (32-byte) key for AES-256"""
    return os.urandom(32)

def encrypt_text(text: str, key: bytes) -> dict:
    """
    Encrypt text using AES-256-CBC with proper padding
    Returns dictionary containing initialization vector and encrypted text
    """
    try:
        # Generate a random IV
        iv = os.urandom(16)
        
        # Create an encryptor object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Convert text to bytes and pad it
        padder = padding.PKCS7(128).padder()
        text_bytes = text.encode('utf-8')
        padded_data = padder.update(text_bytes) + padder.finalize()
        
        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encode in base64 for easy handling
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        
        return {
            'status': 'success',
            'iv': iv_b64,
            'ciphertext': ciphertext_b64
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

def encrypt_file(file_path: str, key: bytes) -> dict:
    """
    Encrypt a file using AES-256-CBC
    Returns dictionary containing initialization vector and encrypted file path
    """
    try:
        # Generate a random IV
        iv = os.urandom(16)
        
        # Create an encryptor object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Create padder
        padder = padding.PKCS7(128).padder()
        
        # Read and encrypt file in chunks
        encrypted_file_path = file_path + '.encrypted'
        chunk_size = 64 * 1024  # 64KB chunks
        
        with open(file_path, 'rb') as f_in, open(encrypted_file_path, 'wb') as f_out:
            # Write IV at the beginning of the file
            f_out.write(iv)
            
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                
                # Pad the last chunk if needed
                if len(chunk) < chunk_size:
                    padded_chunk = padder.update(chunk) + padder.finalize()
                else:
                    padded_chunk = padder.update(chunk)
                
                encrypted_chunk = encryptor.update(padded_chunk)
                f_out.write(encrypted_chunk)
            
            # Write final block
            f_out.write(encryptor.finalize())
        
        return {
            'status': 'success',
            'encrypted_file': encrypted_file_path,
            'iv': base64.b64encode(iv).decode('utf-8')
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }# In algorithms/des/des_encrypt.py

def encrypt_file(file_path, key):
    """
    Encrypts a file using DES encryption
    
    Args:
        file_path (str): Path to the file to encrypt
        key (bytes): 8-byte encryption key
        
    Returns:
        dict: Dictionary with encryption status and information
    """
    try:
        # Generate IV
        iv = get_random_bytes(8)
        
        # Create cipher
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        # Read file
        with open(file_path, 'rb') as file:
            data = file.read()
        
        # Pad data
        padded_data = pad(data, DES.block_size)
        
        # Encrypt data
        encrypted_data = cipher.encrypt(padded_data)
        
        # Create output file name
        file_name = os.path.basename(file_path)
        encrypted_file_path = os.path.join(os.path.dirname(file_path), f"encrypted_{file_name}")
        
        # Save encrypted data to file
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data)
        
        # Return success and necessary information
        return {
            'status': 'success',
            'message': 'File encrypted successfully',
            'encrypted_file_path': encrypted_file_path,
            'iv': iv.hex(),
            'key': key.decode('utf-8', errors='replace')
        }
    
    except Exception as e:
        return {
            'status': 'error',
            'message': f"Error encrypting file: {str(e)}"
        }