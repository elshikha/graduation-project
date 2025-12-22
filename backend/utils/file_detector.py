"""
File Type Detection Utility
Detects file types based on magic bytes and file extensions
"""

def detect_file_type(filename, content):
    """
    Detect file type based on filename and magic bytes
    
    Args:
        filename (str): Name of the file
        content (bytes): File content in bytes
        
    Returns:
        str: File type (PE, ELF, PDF, Office, Mobile App, Unknown)
    """
    filename_lower = filename.lower()
    extension = filename_lower.split('.')[-1] if '.' in filename_lower else ''
    
    # Check magic bytes (first few bytes of file)
    magic_bytes = content[:4] if len(content) >= 4 else b''
    
    # PE files (Windows executables)
    if extension in ['exe', 'dll', 'sys', 'scr', 'cpl']:
        return 'PE'
    if len(magic_bytes) >= 2 and magic_bytes[:2] == b'MZ':  # PE magic number
        return 'PE'
    
    # ELF files (Linux executables)
    if extension in ['elf', 'so', 'bin', 'o']:
        return 'ELF'
    if len(magic_bytes) >= 4 and magic_bytes[:4] == b'\x7fELF':  # ELF magic number
        return 'ELF'
    
    # PDF files
    if extension == 'pdf':
        return 'PDF'
    if len(magic_bytes) >= 4 and magic_bytes[:4] == b'%PDF':  # PDF magic number
        return 'PDF'
    
    # Office files (OOXML format - ZIP based)
    if extension in ['docx', 'xlsx', 'pptx']:
        return 'Office'
    if len(magic_bytes) >= 2 and magic_bytes[:2] == b'PK':  # ZIP magic (OOXML)
        if extension in ['docx', 'xlsx', 'pptx']:
            return 'Office'
    
    # Office files (Old binary format)
    if extension in ['doc', 'xls', 'ppt']:
        return 'Office'
    if len(magic_bytes) >= 4 and magic_bytes[:4] == b'\xd0\xcf\x11\xe0':  # OLE magic
        return 'Office'
    
    # Mobile apps (unsupported)
    if extension in ['apk', 'ipa', 'aab']:
        return 'Mobile App'
    
    # Android APK (ZIP with specific structure)
    if len(magic_bytes) >= 2 and magic_bytes[:2] == b'PK':
        if extension == 'apk':
            return 'Mobile App'
    
    # Archive files
    if extension in ['zip', 'rar', '7z', 'tar', 'gz']:
        return 'Archive'
    
    # Script files
    if extension in ['py', 'js', 'sh', 'bat', 'ps1', 'vbs']:
        return 'Script'
    
    # Unknown
    return 'Unknown'


def is_supported_type(file_type):
    """
    Check if file type is supported for analysis
    
    Args:
        file_type (str): The detected file type
        
    Returns:
        bool: True if supported, False otherwise
    """
    supported_types = ['PE', 'ELF', 'PDF', 'Office']
    return file_type in supported_types


def get_file_info(filename, content):
    """
    Get comprehensive file information
    
    Args:
        filename (str): Name of the file
        content (bytes): File content in bytes
        
    Returns:
        dict: File information including type, size, and magic bytes
    """
    file_type = detect_file_type(filename, content)
    file_size = len(content)
    magic_hex = content[:16].hex() if len(content) >= 16 else content.hex()
    
    return {
        'filename': filename,
        'file_type': file_type,
        'file_size': file_size,
        'magic_bytes': magic_hex,
        'is_supported': is_supported_type(file_type)
    }
