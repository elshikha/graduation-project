"""
Hash Calculation Utility
Calculates various cryptographic hashes for files
"""

import hashlib


def calculate_md5(content):
    """
    Calculate MD5 hash of file content
    
    Args:
        content (bytes): File content in bytes
        
    Returns:
        str: MD5 hash in hexadecimal
    """
    return hashlib.md5(content).hexdigest()


def calculate_sha1(content):
    """
    Calculate SHA-1 hash of file content
    
    Args:
        content (bytes): File content in bytes
        
    Returns:
        str: SHA-1 hash in hexadecimal
    """
    return hashlib.sha1(content).hexdigest()


def calculate_sha256(content):
    """
    Calculate SHA-256 hash of file content
    
    Args:
        content (bytes): File content in bytes
        
    Returns:
        str: SHA-256 hash in hexadecimal
    """
    return hashlib.sha256(content).hexdigest()


def calculate_sha512(content):
    """
    Calculate SHA-512 hash of file content
    
    Args:
        content (bytes): File content in bytes
        
    Returns:
        str: SHA-512 hash in hexadecimal
    """
    return hashlib.sha512(content).hexdigest()


def calculate_all_hashes(content):
    """
    Calculate all common hashes for file content
    
    Args:
        content (bytes): File content in bytes
        
    Returns:
        dict: Dictionary containing all hash values
    """
    return {
        'md5': calculate_md5(content),
        'sha1': calculate_sha1(content),
        'sha256': calculate_sha256(content),
        'sha512': calculate_sha512(content)
    }


def verify_hash(content, hash_value, hash_type='sha256'):
    """
    Verify if a file's hash matches the provided hash value
    
    Args:
        content (bytes): File content in bytes
        hash_value (str): Expected hash value
        hash_type (str): Type of hash (md5, sha1, sha256, sha512)
        
    Returns:
        bool: True if hashes match, False otherwise
    """
    hash_functions = {
        'md5': calculate_md5,
        'sha1': calculate_sha1,
        'sha256': calculate_sha256,
        'sha512': calculate_sha512
    }
    
    if hash_type.lower() not in hash_functions:
        raise ValueError(f"Unsupported hash type: {hash_type}")
    
    calculated_hash = hash_functions[hash_type.lower()](content)
    return calculated_hash.lower() == hash_value.lower()
