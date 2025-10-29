# algorithms/aes/aes_decrypt.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

def decrypt_text(encrypted_data: dict, key: bytes) -> dict:
    """
    Decrypt text using AES-256-CBC
    Takes dictionary containing IV and ciphertext, returns decrypted text
    """
    try:
        # Decode the base64 IV and ciphertext
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Create a decryptor object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return {
            'status': 'success',
            'plaintext': data.decode('utf-8')
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

# In algorithms/des/des_decrypt.py

def decrypt_file(file_path, key, iv):
    """
    Decrypts a file using DES encryption
    
    Args:
        file_path (str): Path to the encrypted file
        key (bytes): 8-byte encryption key
        iv (str): Hexadecimal string of IV used during encryption
        
    Returns:
        dict: Dictionary with decryption status and information
    """
    try:
        # Convert IV from hex string to bytes
        iv_bytes = bytes.fromhex(iv)
        
        # Create cipher
        cipher = DES.new(key, DES.MODE_CBC, iv_bytes)
        
        # Read encrypted file
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        
        # Decrypt data
        decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
        
        # Create output file name
        file_name = os.path.basename(file_path)
        if file_name.startswith("encrypted_"):
            file_name = file_name[10:]  # Remove "encrypted_" prefix
        decrypted_file_path = os.path.join(os.path.dirname(file_path), f"decrypted_{file_name}")
        
        # Save decrypted data to file
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        
        # Return success and necessary information
        return {
            'status': 'success',
            'message': 'File decrypted successfully',
            'decrypted_file_path': decrypted_file_path
        }
    
    except ValueError as e:
        # Handle padding errors
        return {
            'status': 'error',
            'message': f"Invalid padding or key: {str(e)}"
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f"Error decrypting file: {str(e)}"
        }