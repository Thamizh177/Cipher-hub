from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

class RSAEncryption:
    def __init__(self):
        # Generate private/public key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def get_public_key(self):
        # Export public key in PEM format
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def encrypt_text(self, plaintext):
        # Convert string to bytes
        message = plaintext.encode('utf-8')
        
        # Encrypt the message
        ciphertext = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Convert to base64 for easy storage/transmission
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def encrypt_file(self, file_data):
        # Encrypt file data in chunks
        chunk_size = 190  # Maximum size for RSA-2048
        encrypted_chunks = []
        
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            encrypted_chunk = self.public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        
        # Combine all encrypted chunks
        return b''.join(encrypted_chunks)