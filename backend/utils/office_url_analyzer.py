"""
Office URL Analyzer
Extracts and analyzes URLs, external links, and relationships from Office documents
Detects phishing patterns, suspicious domains, and malicious links
"""

import re
import zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

# Try to import olefile
try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False


# Common OOXML relationship namespaces
OOXML_NAMESPACES = {
    'rel': 'http://schemas.openxmlformats.org/package/2006/relationships',
    'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'spread': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
    'pres': 'http://schemas.openxmlformats.org/presentationml/2006/main',
    'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'
}

# URL extraction regex
URL_REGEX = re.compile(
    r'(?:https?://|ftp://|file://|\\\\)'
    r'[\w\-\.:]+(?:/[\w\-\./?%&=@#~\+\*]*)?',
    re.IGNORECASE
)

IP_ADDRESS_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    (r'file://', 'Local File Protocol'),
    (r'\\\\', 'UNC Path'),
    (r'javascript:', 'JavaScript URI'),
    (r'data:', 'Data URI'),
    (r'vbscript:', 'VBScript URI'),
    (r'\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jar|msi|hta)\b', 'Executable Extension'),
    (r'@', 'URL with Authentication'),
    (r'%[0-9a-fA-F]{2}', 'URL Encoded Characters'),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Direct IP Address'),
    (r'pastebin|hastebin|raw\.github', 'Code Hosting Service'),
    (r'bit\.ly|tinyurl|goo\.gl|t\.co|rebrand\.ly', 'URL Shortener'),
    (r'ngrok|serveo|localtunnel', 'Tunneling Service'),
    (r'\.tk|\.ml|\.ga|\.cf|\.gq', 'Free TLD (Often Abused)'),
    (r'download|temp|update|security|microsoft.*login', 'Suspicious Keywords'),
]

# Relationship types that can reference external content
EXTERNAL_REL_TYPES = [
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink',
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject',
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink',
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/image',
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate',
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame'
]


def classify_url_threat(url: str) -> dict:
    """
    Classify URL threat level based on patterns
    
    Args:
        url (str): URL to classify
        
    Returns:
        dict: Threat classification
    """
    threats = []
    threat_score = 0
    
    for pattern, name in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            threats.append(name)
            
            # Score based on severity
            if name in ['Local File Protocol', 'UNC Path', 'JavaScript URI', 'VBScript URI']:
                threat_score += 3
            elif name in ['Executable Extension', 'Direct IP Address', 'Tunneling Service']:
                threat_score += 2
            else:
                threat_score += 1
    
    if threat_score >= 5:
        severity = "critical"
    elif threat_score >= 3:
        severity = "high"
    elif threat_score >= 1:
        severity = "medium"
    else:
        severity = "low"
    
    return {
        "url": url,
        "threats": threats,
        "threat_score": threat_score,
        "severity": severity
    }


def extract_urls_from_text(text: str) -> list:
    """
    Extract URLs from raw text
    
    Args:
        text (str): Text content
        
    Returns:
        list: Extracted URLs
    """
    urls = URL_REGEX.findall(text)
    return list(set(urls))


def extract_ip_addresses(text: str) -> list:
    """
    Extract IP addresses from text
    
    Args:
        text (str): Text content
        
    Returns:
        list: Extracted IP addresses
    """
    ips = IP_ADDRESS_REGEX.findall(text)
    return list(set(ips))


def analyze_ooxml_relationships(file_path: str) -> dict:
    """
    Analyze OOXML relationship files for external references
    
    Args:
        file_path (str): Path to OOXML file
        
    Returns:
        dict: Relationship analysis
    """
    result = {
        "external_links": [],
        "hyperlinks": [],
        "templates": [],
        "ole_objects": [],
        "suspicious_rels": []
    }
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            # Find all relationship files
            rel_files = [f for f in zf.namelist() if f.endswith('.rels')]
            
            for rel_file in rel_files:
                try:
                    content = zf.read(rel_file).decode('utf-8', errors='ignore')
                    root = ET.fromstring(content)
                    
                    # Analyze each relationship
                    for rel in root.findall('.//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship'):
                        rel_type = rel.get('Type', '')
                        target = rel.get('Target', '')
                        target_mode = rel.get('TargetMode', '')
                        
                        # Check for external targets
                        if target_mode == 'External' or target.startswith('http') or target.startswith('file:') or target.startswith('\\\\'):
                            rel_info = {
                                "source": rel_file,
                                "target": target,
                                "type": rel_type.split('/')[-1] if '/' in rel_type else rel_type,
                                "target_mode": target_mode
                            }
                            
                            # Classify by type
                            if 'hyperlink' in rel_type.lower():
                                result['hyperlinks'].append(rel_info)
                            elif 'oleObject' in rel_type:
                                result['ole_objects'].append(rel_info)
                                rel_info['suspicious'] = True
                            elif 'attachedTemplate' in rel_type:
                                result['templates'].append(rel_info)
                                rel_info['suspicious'] = True
                            elif 'externalLink' in rel_type:
                                result['external_links'].append(rel_info)
                            
                            # Check for suspicious patterns
                            classification = classify_url_threat(target)
                            if classification['threat_score'] > 0:
                                rel_info['threat_info'] = classification
                                result['suspicious_rels'].append(rel_info)
                                
                except Exception:
                    continue
                    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def analyze_ole_links(file_path: str) -> dict:
    """
    Analyze OLE document for external links and references
    
    Args:
        file_path (str): Path to OLE file
        
    Returns:
        dict: OLE link analysis
    """
    result = {
        "urls": [],
        "ip_addresses": [],
        "unc_paths": [],
        "embedded_objects": []
    }
    
    if not OLEFILE_AVAILABLE:
        result['error'] = "olefile not installed"
        return result
    
    try:
        if not olefile.isOleFile(file_path):
            result['error'] = "Not a valid OLE file"
            return result
        
        ole = olefile.OleFileIO(file_path)
        
        # Check all streams for URLs
        for entry in ole.listdir():
            stream_path = '/'.join(entry)
            try:
                data = ole.openstream(stream_path).read()
                text = data.decode('utf-8', errors='ignore')
                
                # Extract URLs
                urls = extract_urls_from_text(text)
                for url in urls:
                    classification = classify_url_threat(url)
                    url_info = {
                        "url": url,
                        "source": stream_path,
                        **classification
                    }
                    result['urls'].append(url_info)
                
                # Extract UNC paths
                unc_pattern = r'\\\\[\w\.\-]+\\[\w\$\.\-\\/]+'
                unc_paths = re.findall(unc_pattern, text)
                for path in unc_paths:
                    result['unc_paths'].append({
                        "path": path,
                        "source": stream_path,
                        "severity": "high"
                    })
                
                # Extract IP addresses
                ips = extract_ip_addresses(text)
                for ip in ips:
                    result['ip_addresses'].append({
                        "ip": ip,
                        "source": stream_path
                    })
                    
            except Exception:
                continue
        
        # Check for embedded objects
        embedded_streams = ['/'.join(e) for e in ole.listdir() if 'Object' in '/'.join(e) or 'Ole' in '/'.join(e)]
        for stream in embedded_streams:
            result['embedded_objects'].append({
                "stream": stream,
                "type": "OLE Embedded Object"
            })
        
        ole.close()
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def analyze_document_content_for_urls(file_path: str) -> dict:
    """
    Extract URLs from document content (text content of OOXML)
    
    Args:
        file_path (str): Path to OOXML file
        
    Returns:
        dict: Content URL analysis
    """
    result = {
        "content_urls": [],
        "embedded_urls": []
    }
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            # Read main content files
            content_files = [
                'word/document.xml',
                'xl/sharedStrings.xml',
                'xl/workbook.xml',
                'ppt/presentation.xml'
            ]
            
            for content_file in content_files:
                if content_file in zf.namelist():
                    try:
                        data = zf.read(content_file).decode('utf-8', errors='ignore')
                        urls = extract_urls_from_text(data)
                        
                        for url in urls:
                            classification = classify_url_threat(url)
                            result['content_urls'].append({
                                "url": url,
                                "source": content_file,
                                **classification
                            })
                    except Exception:
                        continue
            
            # Also check slide content for PowerPoint
            slides = [f for f in zf.namelist() if f.startswith('ppt/slides/slide') and f.endswith('.xml')]
            for slide in slides:
                try:
                    data = zf.read(slide).decode('utf-8', errors='ignore')
                    urls = extract_urls_from_text(data)
                    
                    for url in urls:
                        classification = classify_url_threat(url)
                        result['content_urls'].append({
                            "url": url,
                            "source": slide,
                            **classification
                        })
                except Exception:
                    continue
                    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def get_office_url_analysis(file_path: str) -> dict:
    """
    Comprehensive URL and link analysis for Office documents
    
    Args:
        file_path (str): Path to Office file
        
    Returns:
        dict: Complete URL analysis with risk assessment
    """
    result = {
        "total_urls": 0,
        "suspicious_urls": 0,
        "external_references": 0,
        "urls": [],
        "hyperlinks": [],
        "external_links": [],
        "ole_objects": [],
        "templates": [],
        "unc_paths": [],
        "ip_addresses": [],
        "risk_indicators": []
    }
    
    # Try OOXML analysis first
    try:
        with zipfile.ZipFile(file_path, 'r'):
            is_ooxml = True
    except zipfile.BadZipFile:
        is_ooxml = False
    
    if is_ooxml:
        # Analyze relationships
        rel_analysis = analyze_ooxml_relationships(file_path)
        result['hyperlinks'] = rel_analysis.get('hyperlinks', [])
        result['external_links'] = rel_analysis.get('external_links', [])
        result['ole_objects'] = rel_analysis.get('ole_objects', [])
        result['templates'] = rel_analysis.get('templates', [])
        
        # Add suspicious relationships to URLs
        for rel in rel_analysis.get('suspicious_rels', []):
            result['urls'].append({
                "url": rel['target'],
                "source": rel['source'],
                "type": rel['type'],
                **(rel.get('threat_info', {}))
            })
        
        # Analyze content for URLs
        content_analysis = analyze_document_content_for_urls(file_path)
        for url_info in content_analysis.get('content_urls', []):
            # Avoid duplicates
            if url_info['url'] not in [u['url'] for u in result['urls']]:
                result['urls'].append(url_info)
    else:
        # OLE file analysis
        ole_analysis = analyze_ole_links(file_path)
        result['urls'] = ole_analysis.get('urls', [])
        result['unc_paths'] = ole_analysis.get('unc_paths', [])
        result['ip_addresses'] = ole_analysis.get('ip_addresses', [])
        
        for obj in ole_analysis.get('embedded_objects', []):
            result['ole_objects'].append(obj)
    
    # Calculate statistics
    result['total_urls'] = len(result['urls'])
    result['suspicious_urls'] = len([u for u in result['urls'] if u.get('severity') in ['high', 'critical']])
    result['external_references'] = (
        len(result['hyperlinks']) + 
        len(result['external_links']) + 
        len(result['templates']) +
        len(result['ole_objects'])
    )
    
    # Generate risk indicators
    if result['ole_objects']:
        result['risk_indicators'].append(f"OLE Objects Detected ({len(result['ole_objects'])})")
    
    if result['templates']:
        result['risk_indicators'].append(f"External Template References ({len(result['templates'])})")
    
    if result['unc_paths']:
        result['risk_indicators'].append(f"UNC Path References ({len(result['unc_paths'])})")
    
    if result['suspicious_urls'] > 0:
        result['risk_indicators'].append(f"Suspicious URLs ({result['suspicious_urls']})")
    
    # Check for specific threats
    for url_info in result['urls']:
        if 'Executable Extension' in url_info.get('threats', []):
            result['risk_indicators'].append("URL Points to Executable")
            break
    
    for url_info in result['urls']:
        if 'Direct IP Address' in url_info.get('threats', []):
            result['risk_indicators'].append("URL with Direct IP Address")
            break
    
    # Calculate URL risk score
    url_risk_score = 0
    
    for url_info in result['urls']:
        url_risk_score += url_info.get('threat_score', 0) * 0.5
    
    url_risk_score += len(result['ole_objects']) * 2
    url_risk_score += len(result['templates']) * 3
    url_risk_score += len(result['unc_paths']) * 2
    
    result['url_risk_score'] = min(10, round(url_risk_score, 1))
    
    # Determine URL status
    if result['url_risk_score'] >= 7:
        result['url_status'] = "HIGH RISK"
        result['url_status_color'] = "red"
    elif result['url_risk_score'] >= 4:
        result['url_status'] = "SUSPICIOUS"
        result['url_status_color'] = "orange"
    elif result['total_urls'] > 0:
        result['url_status'] = "PRESENT"
        result['url_status_color'] = "yellow"
    else:
        result['url_status'] = "CLEAN"
        result['url_status_color'] = "green"
    
    return result
