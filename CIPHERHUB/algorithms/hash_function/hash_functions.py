# algorithms/hash_function/hash_functions.py
import hashlib

def hash_md5(text):
    """Generate MD5 hash of the input text."""
    return hashlib.md5(text.encode()).hexdigest()

def hash_sha1(text):
    """Generate SHA-1 hash of the input text."""
    return hashlib.sha1(text.encode()).hexdigest()

def hash_sha256(text):
    """Generate SHA-256 hash of the input text."""
    return hashlib.sha256(text.encode()).hexdigest()

def hash_sha512(text):
    """Generate SHA-512 hash of the input text."""
    return hashlib.sha512(text.encode()).hexdigest()

def hash_sha3_256(text):
    """Generate SHA3-256 hash of the input text."""
    return hashlib.sha3_256(text.encode()).hexdigest()

def hash_blake2b(text):
    """Generate BLAKE2b hash of the input text."""
    return hashlib.blake2b(text.encode()).hexdigest()