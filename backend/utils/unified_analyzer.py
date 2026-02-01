"""
Unified File Analysis with CVSS-based Risk Scoring
Combines multiple analyzers and provides standardized CVSS risk assessment
"""

import os
import sys
from pathlib import Path

# Import all analyzers
from .file_analyzer import get_comprehensive_file_info, analyze_pe_header
from .pdf_analyzer import get_comprehensive_pdf_analysis, check_pdf_header
from .cvss_calculator import CVSSCalculator
from .hash_calculator import calculate_hashes
from .strings_analyzer import extract_strings, analyze_suspicious_strings
from .capa_analyzer import CapaAnalyzer
from .die_analyzer import run_die_analysis, get_die_summary


def analyze_file_with_cvss(file_path, file_type=None):
    """
    Perform comprehensive file analysis with CVSS-based risk scoring
    
    Args:
        file_path (str): Path to file to analyze
        file_type (str, optional): File type hint ('PE', 'PDF', etc.)
    
    Returns:
        dict: Unified analysis results with CVSS scoring
    """
    
    if not os.path.exists(file_path):
        return {
            'success': False,
            'error': 'File not found'
        }
    
    # Read file content
    with open(file_path, 'rb') as f:
        content = f.read()
    
    # Detect file type if not provided
    if not file_type:
        file_type = detect_file_type(file_path, content)
    
    # Initialize result structure
    result = {
        'success': True,
        'filename': os.path.basename(file_path),
        'file_size': len(content),
        'file_type': file_type,
        'hashes': calculate_hashes(content),
        'analysis': {}
    }
    
    # Perform type-specific analysis
    if file_type == 'PDF':
        result['analysis'] = analyze_pdf_with_cvss(file_path, content)
    elif file_type == 'PE':
        result['analysis'] = analyze_pe_with_cvss(file_path, content)
    else:
        result['analysis'] = analyze_generic_with_cvss(file_path, content)
    
    # Extract top-level CVSS results for easy access
    if 'cvss_score' in result['analysis']:
        result['cvss_score'] = result['analysis']['cvss_score']
        result['severity'] = result['analysis']['severity']
        result['threat_level'] = result['analysis']['threat_level']
        result['verdict'] = result['analysis']['verdict']
        result['recommendation'] = result['analysis']['recommendation']
    
    return result


def analyze_pdf_with_cvss(file_path, content):
    """
    Analyze PDF file with CVSS scoring
    
    Args:
        file_path (str): Path to PDF file
        content (bytes): File content
    
    Returns:
        dict: PDF analysis with CVSS scoring
    """
    # Use existing comprehensive PDF analyzer (already updated with CVSS)
    pdf_results = get_comprehensive_pdf_analysis(file_path)
    
    return pdf_results


def analyze_pe_with_cvss(file_path, content):
    """
    Analyze PE (executable) file with CVSS scoring
    
    Args:
        file_path (str): Path to PE file
        content (bytes): File content
    
    Returns:
        dict: PE analysis with CVSS scoring
    """
    pe_analysis = {}
    
    # Basic file info
    file_info = get_comprehensive_file_info(file_path, content)
    pe_analysis['file_info'] = file_info
    
    # PE header analysis
    pe_header = analyze_pe_header(file_path)
    pe_analysis['pe_header'] = pe_header
    
    # DIE analysis
    die_results = run_die_analysis(file_path)
    pe_analysis['die'] = die_results
    if 'error' not in die_results:
        pe_analysis['die_summary'] = get_die_summary(die_results)
    
    # CAPA analysis
    try:
        capa = CapaAnalyzer()
        capa_results = capa.analyze(file_path)
        pe_analysis['capa'] = capa_results
    except Exception as e:
        pe_analysis['capa'] = {
            'success': False,
            'error': str(e)
        }
    
    # String analysis
    strings_data = extract_strings(content)
    suspicious_strings = analyze_suspicious_strings(strings_data)
    pe_analysis['strings'] = {
        'total_count': len(strings_data),
        'suspicious': suspicious_strings
    }
    
    # Calculate CVSS score for PE
    cvss_result = CVSSCalculator.calculate_pe_score(pe_analysis)
    
    # Add CVSS results
    pe_analysis['cvss_score'] = cvss_result['cvss_score']
    pe_analysis['severity'] = cvss_result['severity']
    pe_analysis['threat_level'] = cvss_result['threat_level']
    pe_analysis['contributing_factors'] = cvss_result['contributing_factors']
    pe_analysis['recommendation'] = CVSSCalculator.get_recommendation(cvss_result)
    
    # Determine verdict based on CVSS severity
    severity = cvss_result['severity']
    if severity == 'Critical':
        pe_analysis['verdict'] = 'MALICIOUS - High confidence'
    elif severity == 'High':
        pe_analysis['verdict'] = 'DANGEROUS - Further analysis recommended'
    elif severity == 'Medium':
        pe_analysis['verdict'] = 'SUSPICIOUS - Manual review suggested'
    elif severity == 'Low':
        pe_analysis['verdict'] = 'QUESTIONABLE - Proceed with caution'
    else:
        pe_analysis['verdict'] = 'SAFE - No significant threats detected'
    
    return pe_analysis


def analyze_generic_with_cvss(file_path, content):
    """
    Analyze generic/unknown file type with basic CVSS scoring
    
    Args:
        file_path (str): Path to file
        content (bytes): File content
    
    Returns:
        dict: Basic analysis with CVSS scoring
    """
    analysis = {}
    
    # Basic file info
    file_info = get_comprehensive_file_info(file_path, content)
    analysis['file_info'] = file_info
    
    # String analysis
    strings_data = extract_strings(content)
    suspicious_strings = analyze_suspicious_strings(strings_data)
    analysis['strings'] = {
        'total_count': len(strings_data),
        'suspicious': suspicious_strings
    }
    
    # Basic threat indicators for generic files
    threat_indicators = {}
    
    # High entropy suggests encryption/packing
    entropy = file_info.get('entropy', 0)
    if entropy >= 7.5:
        threat_indicators['high_entropy'] = 1
        threat_indicators['packer_detected'] = 1
    
    # Suspicious strings
    if len(suspicious_strings) > 0:
        threat_indicators['suspicious_strings'] = min(len(suspicious_strings), 5)
    
    # Calculate CVSS score
    cvss_result = CVSSCalculator.calculate_cvss_score(threat_indicators)
    
    # Add CVSS results
    analysis['cvss_score'] = cvss_result['cvss_score']
    analysis['severity'] = cvss_result['severity']
    analysis['threat_level'] = cvss_result['threat_level']
    analysis['contributing_factors'] = cvss_result['contributing_factors']
    analysis['recommendation'] = CVSSCalculator.get_recommendation(cvss_result)
    
    # Determine verdict
    severity = cvss_result['severity']
    if severity == 'Critical':
        analysis['verdict'] = 'MALICIOUS - High confidence'
    elif severity == 'High':
        analysis['verdict'] = 'DANGEROUS - Further analysis recommended'
    elif severity == 'Medium':
        analysis['verdict'] = 'SUSPICIOUS - Manual review suggested'
    elif severity == 'Low':
        analysis['verdict'] = 'QUESTIONABLE - Proceed with caution'
    else:
        analysis['verdict'] = 'SAFE - No significant threats detected'
    
    return analysis


def detect_file_type(file_path, content):
    """
    Detect file type based on magic bytes and file extension
    
    Args:
        file_path (str): Path to file
        content (bytes): File content
    
    Returns:
        str: File type ('PE', 'PDF', 'ELF', 'Unknown')
    """
    # Get extension
    ext = Path(file_path).suffix.lower()
    
    # Check magic bytes
    if len(content) < 4:
        return 'Unknown'
    
    magic = content[:4]
    
    # PDF
    if magic[:4] == b'%PDF' or ext == '.pdf':
        return 'PDF'
    
    # PE (Windows executable)
    if magic[:2] == b'MZ' or ext in ['.exe', '.dll', '.sys']:
        return 'PE'
    
    # ELF (Linux executable)
    if magic[:4] == b'\x7fELF' or ext in ['.elf', '.so']:
        return 'ELF'
    
    # Office documents
    if magic[:2] == b'PK' and ext in ['.docx', '.xlsx', '.pptx']:
        return 'Office'
    
    if magic == b'\xd0\xcf\x11\xe0':
        return 'Office'
    
    return 'Unknown'
