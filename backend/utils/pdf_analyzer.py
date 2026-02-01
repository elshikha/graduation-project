"""
PDF Analysis Utility
Analyzes PDF files for malicious characteristics, suspicious elements, and metadata
Uses external tools: YARA64 and peepdf
"""

import os
import sys
import re
import hashlib
import subprocess
import json
from decimal import Decimal
from .cvss_calculator import CVSSCalculator

# Import pdfid from local utils
try:
    from . import pdfid
except ImportError:
    try:
        import pdfid # type: ignore
    except ImportError:
        pdfid = None

# External tools paths
YARA_EXE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'External', 'Yara', 'yara64.exe')
YARA_RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'External', 'Yara', 'rules', 'pdf', 'pdf_rules.yara')
PEEPDF_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'External', 'peepdf', 'peepdf.py')
PYTHON2_PATH = 'python2'  # Assumes python2 is in PATH


def analyze_pdf_structure(file_path):
    """
    Analyze PDF structure using PDFiD to detect suspicious elements
    
    Args:
        file_path (str): Path to PDF file
        
    Returns:
        dict: PDF analysis results with risk indicators
    """
    if not pdfid:
        return {'error': 'PDFiD library not available'}
    
    try:
        # Run PDFiD analysis
        pdfid_output = pdfid.PDFiD2String(pdfid.PDFiD(file_path, True, True, False, True), True)
        
        analysis = {
            'suspicious_elements': [],
            'metadata': {},
            'entropy': {},
            'warnings': []
        }
        
        # Parse PDFiD output
        for line in pdfid_output.split('\n'):
            parts = re.split(r'[\s]+', line)
            
            # PDF Header version
            if "PDF Header" in line:
                version = parts[3] if len(parts) > 3 else 'Unknown'
                analysis['metadata']['pdf_version'] = version
                if not re.match(r'%PDF-1\.\d', version):
                    analysis['suspicious_elements'].append(f'Invalid PDF version: {version}')
            
            # JavaScript
            elif "/JS " in line and len(parts) > 2:
                js_count = int(parts[2])
                if js_count > 0:
                    analysis['metadata']['javascript_count'] = js_count
                    analysis['suspicious_elements'].append(f'Contains JavaScript ({js_count} instances)')
            
            # AcroForm
            elif "/AcroForm " in line and len(parts) > 2:
                acroform_count = int(parts[2])
                if acroform_count > 0:
                    analysis['metadata']['acroform_count'] = acroform_count
                    analysis['suspicious_elements'].append('Contains AcroForm')
            # Automatic Actions
            elif "/AA " in line and len(parts) > 2:
                aa_count = int(parts[2])
                if aa_count > 0:
                    analysis['metadata']['auto_action_count'] = aa_count
                    analysis['suspicious_elements'].append('Contains Automatic Actions')
            
            # OpenAction
            elif "/OpenAction " in line and len(parts) > 2:
                oa_count = int(parts[2])
                if oa_count > 0:
                    analysis['metadata']['open_action_count'] = oa_count
                    analysis['suspicious_elements'].append('Contains OpenAction')
            
            # Launch Action
            elif "/Launch " in line and len(parts) > 2:
                launch_count = int(parts[2])
                if launch_count > 0:
                    analysis['metadata']['launch_count'] = launch_count
                    analysis['suspicious_elements'].append('Contains Launch Action (CRITICAL)')
            
            # Embedded Files
            elif "/EmbeddedFiles " in line and len(parts) > 2:
                embed_count = int(parts[2])
                if embed_count > 0:
                    analysis['metadata']['embedded_files'] = embed_count
                    analysis['suspicious_elements'].append(f'Contains embedded files ({embed_count})')
            
            # Entropy analysis
            elif "Total entropy:" in line and len(parts) > 3:
                analysis['entropy']['total'] = float(parts[3])
            elif "Entropy inside streams:" in line and len(parts) > 4:
                analysis['entropy']['inside_streams'] = float(parts[4])
            elif "Entropy outside streams:" in line and len(parts) > 4:
                analysis['entropy']['outside_streams'] = float(parts[4])
            
            # Page counts
            elif "/Page " in line and len(parts) > 2:
                analysis['metadata']['page_count'] = int(parts[2])
            elif "/Pages " in line and len(parts) > 2:
                analysis['metadata']['pages_object_count'] = int(parts[2])
        
        # Analyze entropy for anomalies
        if analysis['entropy']:
            analyze_pdf_entropy(analysis)
        
        # Analyze page counts
        analyze_page_counts(analysis)
        
        return analysis
        
    except Exception as e:
        return {'error': f'PDF analysis failed: {str(e)}'}


def analyze_pdf_entropy(analysis):
    """
    Analyze PDF entropy for suspicious patterns
    
    Args:
        analysis (dict): Analysis results dictionary to update
    """
    entropy = analysis.get('entropy', {})
    
    if not all(k in entropy for k in ['total', 'inside_streams', 'outside_streams']):
        return
    
    total = entropy['total']
    inside = entropy['inside_streams']
    outside = entropy['outside_streams']
    
    # High total entropy is VERY suspicious for PDFs
    if total >= 7.8:
        analysis['warnings'].append('CRITICAL: Very high entropy detected - likely encrypted/packed malware')
    elif total >= 7.0:
        analysis['warnings'].append('HIGH: High entropy detected - possible encryption/packing')
    
    # Check for suspicious entropy patterns
    # Low entropy (possible NOP-sled or padding)
    if total <= 2.0 or inside <= 2.0:
        analysis['warnings'].append('LOW entropy detected - possible obfuscation or padding')
    
    # Outside entropy of 0 with high inside entropy is EXTREMELY suspicious
def analyze_page_counts(analysis):
    """
    Analyze page count anomalies
    
    Args:
        analysis (dict): Analysis results dictionary to update
    """
    metadata = analysis.get('metadata', {})
    page_count = metadata.get('page_count', 0)
    pages_object = metadata.get('pages_object_count', 0)
    
    # Single page PDFs are common for invoices, forms, etc. - not inherently suspicious
    # Only flag if combined with other suspicious elements
    if page_count == 1 and len(analysis.get('suspicious_elements', [])) > 0:
        analysis['warnings'].append('Single page PDF with suspicious elements')
    
    if page_count == 0 and pages_object == 0:
        analysis['warnings'].append('Both /Page and /Pages = 0 (suspicious)')
    elif page_count == 0 and pages_object > 0:
        analysis['warnings'].append('No individual pages defined')


def scan_pdf_with_yara(file_path):
    """
    Scan PDF file with YARA using external yara64.exe
    
    Args:
        file_path (str): Path to PDF file
        
    Returns:
        dict: YARA scan results with matches and scores
    """
    yara_results = {
        'matches': [],
        'rule_count': 0
    }
    
    if not os.path.exists(YARA_EXE):
        yara_results['error'] = 'YARA executable not found'
        return yara_results
    
    if not os.path.exists(YARA_RULES):
        yara_results['error'] = 'YARA rules file not found'
        return yara_results
    
    try:
        # Run YARA scan
        result = subprocess.run(
            [YARA_EXE, YARA_RULES, file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Parse YARA output (format: rule_name file_path)
        lines = result.stdout.strip().split('\n')
        for line in lines:
            if not line or line.startswith('warning:'):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                rule_name = parts[0]
                
                match_info = {
                    'rule': rule_name,
                    'tags': ['PDF']
                }
                
                yara_results['matches'].append(match_info)
                yara_results['rule_count'] += 1
        
    except subprocess.TimeoutExpired:
        yara_results['error'] = 'YARA scan timed out'
    except Exception as e:
        yara_results['error'] = f'YARA scan failed: {str(e)}'
    
    return yara_results


def analyze_with_peepdf(file_path):
    """
    Analyze PDF using peepdf (Python 2)
    
    Args:
        file_path (str): Path to PDF file
        
    Returns:
        dict: peepdf analysis results
    """
    peepdf_results = {
        'info': {},
        'suspicious_elements': []
    }
    
    if not os.path.exists(PEEPDF_PY):
        peepdf_results['error'] = 'peepdf not found'
        return peepdf_results
    
    try:
        # Run peepdf to get file info (no interactive mode, just parse output)
        result = subprocess.run(
            [PYTHON2_PATH, PEEPDF_PY, file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout + result.stderr  # Combine stdout and stderr
        
        # Parse peepdf output
        for line in output.split('\n'):
            # Basic file info
            if line.startswith('MD5:'):
                peepdf_results['info']['md5'] = line.split(':', 1)[1].strip()
            elif line.startswith('SHA1:'):
                peepdf_results['info']['sha1'] = line.split(':', 1)[1].strip()
            elif line.startswith('SHA256:'):
                peepdf_results['info']['sha256'] = line.split(':', 1)[1].strip()
            elif line.startswith('Size:'):
                peepdf_results['info']['size'] = line.split(':', 1)[1].strip()
            elif line.startswith('Version:'):
                peepdf_results['info']['version'] = line.split(':', 1)[1].strip()
            elif line.startswith('Binary:'):
                peepdf_results['info']['binary'] = line.split(':', 1)[1].strip()
            elif line.startswith('Linearized:'):
                peepdf_results['info']['linearized'] = line.split(':', 1)[1].strip()
            elif line.startswith('Encrypted:'):
                encrypted = line.split(':', 1)[1].strip()
                peepdf_results['info']['encrypted'] = encrypted
                if encrypted == 'True':
                    peepdf_results['suspicious_elements'].append('PDF is encrypted')
            elif line.startswith('Objects:'):
                peepdf_results['info']['objects'] = line.split(':', 1)[1].strip()
            elif line.startswith('Streams:'):
                peepdf_results['info']['streams'] = line.split(':', 1)[1].strip()
            elif line.startswith('URIs:'):
                uris = line.split(':', 1)[1].strip()
                if int(uris) > 0:
                    peepdf_results['suspicious_elements'].append(f'Contains {uris} URIs')
            elif line.startswith('Errors:'):
                errors = line.split(':', 1)[1].strip()
                if int(errors) > 0:
                    peepdf_results['suspicious_elements'].append(f'{errors} parsing errors')
        
    except subprocess.TimeoutExpired:
        peepdf_results['error'] = 'peepdf analysis timed out'
    except Exception as e:
        peepdf_results['error'] = f'peepdf analysis failed: {str(e)}'
    
    return peepdf_results


def get_comprehensive_pdf_analysis(file_path):
    """
    Perform comprehensive PDF analysis combining multiple tools
    
    Args:
        file_path (str): Path to PDF file
        
    Returns:
        dict: Complete PDF analysis results
    """
    results = {
        'filename': os.path.basename(file_path),
        'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
    }
    
    # PDF structure analysis (PDFiD - legacy)
    structure_analysis = analyze_pdf_structure(file_path)
    results['structure'] = structure_analysis
    
    # peepdf analysis
    peepdf_analysis = analyze_with_peepdf(file_path)
    results['peepdf'] = peepdf_analysis
    
    # Metadata extraction
    metadata = extract_pdf_metadata(file_path)
    results['metadata'] = metadata
    
    # YARA scanning with external yara64.exe
    yara_results = scan_pdf_with_yara(file_path)
    results['yara'] = yara_results
    
    # Calculate CVSS-based risk score
    cvss_result = CVSSCalculator.calculate_pdf_score(results)
    
    # Add CVSS results to output
    results['cvss_score'] = cvss_result['cvss_score']
    results['severity'] = cvss_result['severity']
    results['threat_level'] = cvss_result['threat_level']
    results['contributing_factors'] = cvss_result['contributing_factors']
    results['recommendation'] = CVSSCalculator.get_recommendation(cvss_result)
    
    # Determine verdict based on CVSS severity
    severity = cvss_result['severity']
    if severity == 'Critical':
        results['verdict'] = 'MALICIOUS - High confidence'
    elif severity == 'High':
        results['verdict'] = 'DANGEROUS - Further analysis recommended'
    elif severity == 'Medium':
        results['verdict'] = 'SUSPICIOUS - Manual review suggested'
    elif severity == 'Low':
        results['verdict'] = 'QUESTIONABLE - Proceed with caution'
    else:
        results['verdict'] = 'SAFE - No significant threats detected'
    
    return results


def extract_pdf_metadata(file_path):
    """
    Extract PDF metadata using pdfinfo if available
    
    Args:
        file_path (str): Path to PDF file
        
    Returns:
        dict: PDF metadata
    """
    metadata = {}
    
    try:
        # Try using pdfinfo command
        result = subprocess.run(
            ['pdfinfo', file_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[key.strip()] = value.strip()
        
        # Check stderr for warnings
        if result.stderr:
            warnings = []
            for line in result.stderr.split('\n'):
                if re.search(r'Unterminated hex string|Loop in Pages tree|Illegal digit', line):
                    warnings.append('Malformed PDF structure detected')
                elif re.search(r'Unexpected end of file|End of file inside array', line):
                    warnings.append('EOF problem detected')
                elif re.search(r'Invalid XRef|No valid XRef|Couldn\'t read xref', line):
                    warnings.append('Invalid XREF table')
            
            if warnings:
                metadata['warnings'] = warnings
    
    except FileNotFoundError:
        metadata['info'] = 'pdfinfo not available on system'
    except subprocess.TimeoutExpired:
        metadata['error'] = 'pdfinfo timeout'
    except Exception as e:
        metadata['error'] = str(e)
    
    return metadata


def check_pdf_header(file_path):
    """
    Check if file has valid PDF header within first 1024 bytes
    
    Args:
        file_path (str): Path to file
        
    Returns:
        bool: True if valid PDF header found
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(1024)
            return b'%PDF' in header
    except Exception:
        return False
def check_pdf_header(file_path):
    """
    Check if file has valid PDF header within first 1024 bytes
    
    Args:
        file_path (str): Path to file
        
    Returns:
        bool: True if valid PDF header found
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(1024)
            return b'%PDF' in header
    except Exception:
        return False
