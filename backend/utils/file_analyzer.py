"""
File Analysis Utility
Provides comprehensive file analysis including entropy, timestamps, and PE header analysis
"""

import os
import math
import time
import hashlib


def calculate_file_entropy(content):
    """
    Calculate Shannon entropy of file content
    Entropy indicates randomness - high entropy (close to 8) suggests encryption/compression
    
    Args:
        content (bytes): File content in bytes
        
    Returns:
        float: Entropy value (0-8)
    """
    if not content:
        return 0.0
    
    # Count occurrences of each byte value
    byte_counts = {}
    for byte in content:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate entropy using Shannon entropy formula
    total_bytes = len(content)
    entropy = 0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    
    return round(entropy, 4)


def get_file_timestamps(file_path):
    """
    Get file creation, modification, and access times
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        dict: Dictionary containing ctime, mtime, atime
    """
    try:
        stat_info = os.stat(file_path)
        return {
            'ctime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_ctime)),
            'mtime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_mtime)),
            'atime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_atime))
        }
    except Exception as e:
        return {
            'ctime': 'Unknown',
            'mtime': 'Unknown',
            'atime': 'Unknown',
            'error': str(e)
        }


def calculate_blake2b(content):
    """
    Calculate BLAKE2b hash of file content
    
    Args:
        content (bytes): File content in bytes
        
    Returns:
        str: BLAKE2b hash in hexadecimal
    """
    return hashlib.blake2b(content).hexdigest()


def analyze_pe_header(file_path):
    """
    Analyze PE (Portable Executable) file header
    Requires pefile library
    Integrates DIE (Detect It Easy) analysis for compiler/packer detection
    
    Args:
        file_path (str): Path to PE file
        
    Returns:
        dict: PE header information or error message
    """
    try:
        import pefile
        from .die_analyzer import run_die_analysis, get_die_summary
        
        pe = pefile.PE(file_path)
        
        # Extract sections information
        sections = []
        for section in pe.sections:
            sections.append({
                'name': section.Name.decode().rstrip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': hex(section.SizeOfRawData),
                'entropy': section.get_entropy()
            })
        
        # Extract imported DLLs
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports.append(entry.dll.decode())
        
        pe_info = {
            'machine': hex(pe.FILE_HEADER.Machine),
            'machine_type': pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, 'Unknown'),
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pe.FILE_HEADER.TimeDateStamp)),
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            'subsystem': pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, 'Unknown'),
            'sections': sections,
            'imports': imports[:20],  # Limit to first 20 DLLs
            'is_dll': pe.is_dll(),
            'is_exe': pe.is_exe()
        }
        
        # Run DIE analysis for compiler/packer detection
        die_result = run_die_analysis(file_path)
        if 'error' not in die_result:
            pe_info['die_analysis'] = die_result
            pe_info['die_summary'] = get_die_summary(die_result)
        else:
            pe_info['die_analysis'] = {'note': 'DIE analysis unavailable', 'error': die_result.get('error')}
        
        pe.close()
        return pe_info
        
    except ImportError:
        return {'error': 'pefile library not installed. Run: pip install pefile'}
    except Exception as e:
        return {'error': f'Failed to analyze PE header: {str(e)}'}


def get_comprehensive_file_info(file_path, content):
    """
    Get comprehensive file information including size, entropy, timestamps
    
    Args:
        file_path (str): Path to the file
        content (bytes): File content in bytes
        
    Returns:
        dict: Comprehensive file information
    """
    file_info = {
        'name': os.path.basename(file_path),
        'size': len(content),
        'size_kb': round(len(content) / 1024, 2),
        'size_mb': round(len(content) / (1024 * 1024), 2),
        'entropy': calculate_file_entropy(content),
    }
    
    # Add timestamps if file exists
    if os.path.exists(file_path):
        file_info.update(get_file_timestamps(file_path))
    
    # Add entropy interpretation
    if file_info['entropy'] > 7.5:
        file_info['entropy_status'] = 'High (Possibly encrypted/packed)'
    elif file_info['entropy'] > 6.0:
        file_info['entropy_status'] = 'Medium (Compressed or mixed content)'
    else:
        file_info['entropy_status'] = 'Low (Plain text or low complexity)'
    
    return file_info


def search_file_by_hash(target_hash, search_directory, hash_type='sha256'):
    """
    Search for files matching a specific hash in a directory
    
    Args:
        target_hash (str): Hash to search for
        search_directory (str): Directory to search in
        hash_type (str): Type of hash (md5, sha1, sha256)
        
    Returns:
        list: List of file paths matching the hash
    """
    matching_files = []
    
    for root, _, files in os.walk(search_directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                if hash_type == 'md5':
                    file_hash = hashlib.md5(content).hexdigest()
                elif hash_type == 'sha1':
                    file_hash = hashlib.sha1(content).hexdigest()
                else:  # sha256
                    file_hash = hashlib.sha256(content).hexdigest()
                
                if file_hash == target_hash:
                    matching_files.append(file_path)
            except Exception:
                continue
    
    return matching_files
