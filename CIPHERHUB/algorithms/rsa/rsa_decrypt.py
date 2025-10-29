from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

class RSADecryption:
    def __init__(self, private_key):
        self.private_key = private_key
    
    def decrypt_text(self, encrypted_text):
        # Convert from base64 back to bytes
        ciphertext = base64.b64decode(encrypted_text.encode('utf-8'))
        
        # Decrypt the message
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext.decode('utf-8')
    
    def decrypt_file(self, encrypted_data):
        # Decrypt file data in chunks
        chunk_size = 256  # Size of encrypted chunk for RSA-2048
        decrypted_chunks = []
        
        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            decrypted_chunk = self.private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)
        
        # Combine all decrypted chunks
        return b''.join(decrypted_chunks)