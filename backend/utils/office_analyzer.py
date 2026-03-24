"""
Office Document Analyzer
Comprehensive analysis of Microsoft Office files matching office.py functionality
Includes TrID identification, metadata extraction, OLE analysis, entropy, and URL extraction
"""

import os
import math
import hashlib
import binascii
import zipfile
import re
import xml.etree.ElementTree as ET

# Try to import olefile for OLE analysis
try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False
    print("[WARNING] olefile not installed. OLE analysis will be limited.")

# Try to import oletools
try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False
    print("[WARNING] oletools not installed. Macro analysis will be limited.")

# Try to import YARA
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# ==========================================
# FILE SIGNATURES (TrID-style)
# ==========================================
FILE_SIGNATURES = {
    b'D0CF11E0': 'OLE Compound File (Legacy Office)',
    b'504B0304': 'ZIP Archive (OOXML/OpenDocument)',
    b'7B5C727466': 'Rich Text Format (RTF)',
    b'25504446': 'PDF Document',
    b'4D5A': 'Windows Executable (PE)',
    b'7F454C46': 'ELF Binary (Linux)',
}

SUPPORTED_OFFICE_TYPES = [
    'OLE Compound File (Legacy Office)',
    'ZIP Archive (OOXML/OpenDocument)',
    'Rich Text Format (RTF)'
]

# Suspicious extensions
SUSPICIOUS_EXTS = ['.exe', '.bat', '.cmd', '.scr', '.js', '.vbs', '.ps1', '.hta', '.dll', '.bin']

# Obfuscation patterns for VMonkey-style emulation
OBFUSCATION_PATTERNS = [
    (r'Chr\(\w+\)', 'Character Casting (Chr)'),
    (r'ChrW\(\w+\)', 'Unicode Casting (ChrW)'),
    (r'ChrB\(\w+\)', 'Byte Character Casting (ChrB)'),
    (r'StrReverse\(', 'String Reversal'),
    (r'Base64', 'Base64 Encoding'),
    (r'Xor', 'XOR Encryption'),
    (r'Hex\(', 'Hex Conversion'),
    (r'Replace\(', 'String Replace'),
    (r'Mid\(', 'String Mid'),
    (r'Split\(', 'String Split'),
]

# Safe schema namespaces (to ignore in URL scanning)
SCHEMA_NAMESPACES = [
    "http://schemas.openxmlformats.org",
    "http://schemas.microsoft.com",
    "http://purl.org",
    "http://www.w3.org",
    "urn:schemas-microsoft-com",
    "http://www.w3.org/TR/REC-html40"
]

# URL regex pattern
URL_REGEX = re.compile(
    r'(?:(?:https?|ftp|file)://|mailto:|www\.|ftp\.)'
    r'(?:\S+(?::\S*)?@)?'
    r'(?:[-a-zA-Z0-9.]+(?:\.[a-zA-Z]{2,})?)'
    r'(?::[0-9]{1,5})?'
    r'(?:/[-\w./?%&+=$!*\\(\\),~#]*)?',
    re.IGNORECASE
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0-8 scale)"""
    if not data:
        return 0.0
    counts = {b: data.count(b) for b in set(data)}
    total = len(data)
    return round(-sum((c/total) * math.log2(c/total) for c in counts.values()), 2)


def hex_dump(data: bytes, length: int = 32) -> str:
    """Convert bytes to formatted hex dump"""
    hex_str = binascii.hexlify(data[:length]).decode()
    return " ".join([hex_str[i:i+2].upper() for i in range(0, len(hex_str), 2)])


def calculate_hashes(file_path: str) -> dict:
    """Calculate cryptographic hashes for the file"""
    hashes = {'md5': 'Error', 'sha1': 'Error', 'sha256': 'Error', 'sha512': 'Error'}
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            hashes['sha512'] = hashlib.sha512(data).hexdigest()
    except Exception:
        pass
    return hashes


def is_safe_schema(link: str) -> bool:
    """Check if URL is a safe internal schema namespace"""
    if not link:
        return True
    for schema in SCHEMA_NAMESPACES:
        if schema in link:
            return True
    return False


def score_link(url: str) -> tuple:
    """Score a URL for maliciousness"""
    score = 0
    if url.lower().startswith("file:"):
        score += 5
    if url.lower().startswith("ftp:"):
        score += 3
    if re.search(r'https?://\d{1,3}\.\d{1,3}', url):
        score += 5
    for ext in SUSPICIOUS_EXTS:
        if url.lower().endswith(ext):
            score += 5
    if len(url) > 120:
        score += 2
    if '@' in url:
        score += 3
    
    if score >= 5:
        return score, "MALICIOUS"
    elif score > 0:
        return score, "SUSPICIOUS"
    return score, "SAFE"


# ==========================================
# TrID - FILE IDENTIFICATION
# ==========================================
def identify_file_type(file_path: str) -> tuple:
    """
    Identify file type using magic bytes (TrID-style)
    Returns: (type_name, magic_hex)
    """
    # Normalize path
    file_path = os.path.normpath(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            head = f.read(16)
        
        if not head or len(head) < 4:
            return "Empty or Corrupt File", ""
        
        head_hex = binascii.hexlify(head).upper().decode()
        
        for sig, name in FILE_SIGNATURES.items():
            sig_hex = sig.decode().upper()
            if head_hex.startswith(sig_hex):
                return name, head_hex[:20]
        
        return "Unknown Binary Data", head_hex[:20]
    except FileNotFoundError:
        return "File Not Found", ""
    except PermissionError:
        return "Permission Denied", ""
    except Exception as e:
        return f"Read Error: {str(e)[:50]}", ""


# ==========================================
# METADATA EXTRACTION
# ==========================================
def extract_metadata(file_path: str, type_name: str) -> dict:
    """Extract metadata from Office document"""
    meta = {
        "author": "N/A",
        "last_modified_by": "N/A",
        "created": "N/A",
        "modified": "N/A",
        "title": "N/A",
        "subject": "N/A",
        "company": "N/A",
        "application": "N/A"
    }
    
    # OOXML (docx, pptx, xlsx)
    if "ZIP Archive" in type_name:
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                if 'docProps/core.xml' in zf.namelist():
                    with zf.open('docProps/core.xml') as f:
                        tree = ET.parse(f)
                        root = tree.getroot()
                        ns = {
                            'dc': 'http://purl.org/dc/elements/1.1/',
                            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                            'dcterms': 'http://purl.org/dc/terms/'
                        }
                        
                        creator = root.find('dc:creator', ns)
                        if creator is not None and creator.text:
                            meta['author'] = creator.text
                        
                        title = root.find('dc:title', ns)
                        if title is not None and title.text:
                            meta['title'] = title.text
                        
                        subject = root.find('dc:subject', ns)
                        if subject is not None and subject.text:
                            meta['subject'] = subject.text
                        
                        last_mod = root.find('cp:lastModifiedBy', ns)
                        if last_mod is not None and last_mod.text:
                            meta['last_modified_by'] = last_mod.text
                        
                        created = root.find('dcterms:created', ns)
                        if created is not None and created.text:
                            meta['created'] = created.text
                        
                        modified = root.find('dcterms:modified', ns)
                        if modified is not None and modified.text:
                            meta['modified'] = modified.text
                
                # App metadata
                if 'docProps/app.xml' in zf.namelist():
                    with zf.open('docProps/app.xml') as f:
                        tree = ET.parse(f)
                        root = tree.getroot()
                        ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
                        
                        company = root.find('ep:Company', ns)
                        if company is not None and company.text:
                            meta['company'] = company.text
                        
                        app = root.find('ep:Application', ns)
                        if app is not None and app.text:
                            meta['application'] = app.text
        except Exception:
            pass

    # OLE (doc, ppt, xls)
    elif "OLE Compound" in type_name and OLEFILE_AVAILABLE:
        try:
            ole = olefile.OleFileIO(file_path)
            m = ole.get_metadata()
            if m:
                if m.author:
                    meta['author'] = m.author.decode('utf-8', errors='ignore')
                if m.last_saved_by:
                    meta['last_modified_by'] = m.last_saved_by.decode('utf-8', errors='ignore')
                if m.create_time:
                    meta['created'] = str(m.create_time)
                if m.last_saved_time:
                    meta['modified'] = str(m.last_saved_time)
                if m.title:
                    meta['title'] = m.title.decode('utf-8', errors='ignore')
                if m.subject:
                    meta['subject'] = m.subject.decode('utf-8', errors='ignore')
                if m.company:
                    meta['company'] = m.company.decode('utf-8', errors='ignore')
                if m.creating_application:
                    meta['application'] = m.creating_application.decode('utf-8', errors='ignore')
            ole.close()
        except Exception:
            pass
    
    return meta


# ==========================================
# OLETIME - STREAM TIMESTAMPS
# ==========================================
def analyze_oletimes(file_path: str) -> list:
    """Analyze OLE stream timestamps"""
    timestamps = []
    if not OLEFILE_AVAILABLE:
        return timestamps
    
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            for entry in ole.listdir(streams=True, storages=True):
                path = "/".join(entry)
                mtime = ole.getmtime(entry)
                ctime = ole.getctime(entry)
                t_str = ""
                if mtime:
                    t_str += f"Modified: {mtime} "
                if ctime:
                    t_str += f"Created: {ctime}"
                if t_str:
                    timestamps.append({"name": path, "time": t_str.strip()})
            ole.close()
    except Exception:
        pass
    return timestamps


# ==========================================
# OLEMAP - SECTOR ANALYSIS
# ==========================================
def analyze_sectors(file_path: str) -> dict:
    """Analyze OLE sector structure"""
    map_data = {"total_sectors": 0, "sector_size": 0, "slack_space": 0, "mini_sector_size": 0}
    if not OLEFILE_AVAILABLE:
        return map_data
    
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            map_data["sector_size"] = ole.sectorsize
            map_data["mini_sector_size"] = ole.minisectorcutoff
            file_size = os.path.getsize(file_path)
            map_data["total_sectors"] = math.ceil(file_size / ole.sectorsize)
            map_data["slack_space"] = (map_data["total_sectors"] * ole.sectorsize) - file_size
            ole.close()
    except Exception:
        pass
    return map_data


# ==========================================
# URL EXTRACTION
# ==========================================
def extract_all_urls(file_path: str) -> list:
    """Extract all URLs from Office document"""
    found_urls = []
    seen = set()
    
    # A: ZIP/OOXML Scan
    if zipfile.is_zipfile(file_path):
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                for filename in zf.namelist():
                    # 1. Parse Relationships (Hidden Targets)
                    if filename.endswith('.rels'):
                        try:
                            with zf.open(filename) as f:
                                tree = ET.parse(f)
                                root = tree.getroot()
                                for elem in root.iter():
                                    if 'Target' in elem.attrib:
                                        target = elem.attrib['Target']
                                        target_mode = elem.attrib.get('TargetMode', '')
                                        
                                        # External links or suspicious
                                        if target_mode == 'External' or target.startswith(('http', 'https', 'ftp', 'file:', '\\\\')):
                                            if not is_safe_schema(target) and target not in seen:
                                                seen.add(target)
                                                score, status = score_link(target)
                                                found_urls.append({
                                                    "url": target,
                                                    "status": status,
                                                    "source": "Relationship Target",
                                                    "score": score
                                                })
                        except Exception:
                            pass

                    # 2. Text Content Scan
                    if filename.endswith('.xml'):
                        try:
                            data = zf.read(filename)
                            text_content = data.decode('utf-8', errors='ignore')
                            matches = URL_REGEX.findall(text_content)
                            for url in matches:
                                if is_safe_schema(url) or url in seen:
                                    continue
                                seen.add(url)
                                score, status = score_link(url)
                                found_urls.append({
                                    "url": url,
                                    "status": status,
                                    "source": f"XML Content ({filename})",
                                    "score": score
                                })
                        except Exception:
                            pass
        except Exception:
            pass
    
    # B: Raw Data Scan
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            text_content = data.decode('latin-1', errors='ignore')
            matches = URL_REGEX.findall(text_content)
            for url in matches:
                if is_safe_schema(url) or url in seen:
                    continue
                seen.add(url)
                score, status = score_link(url)
                found_urls.append({
                    "url": url,
                    "status": status,
                    "source": "Raw Data",
                    "score": score
                })
    except Exception:
        pass
    
    return found_urls


# ==========================================
# VMONKEY - HEURISTIC EMULATION
# ==========================================
def heuristic_emulation(vba_code: str) -> list:
    """Detect obfuscation patterns in VBA code (VMonkey-style)"""
    heuristics = []
    for pattern, name in OBFUSCATION_PATTERNS:
        matches = re.findall(pattern, vba_code, re.IGNORECASE)
        if len(matches) > 5:
            heuristics.append({
                "pattern": name,
                "count": len(matches),
                "severity": "high" if len(matches) > 15 else "medium"
            })
    return heuristics


# ==========================================
# MACRO ANALYSIS
# ==========================================
def analyze_macros(file_path: str) -> dict:
    """Analyze VBA and XLM macros"""
    result = {
        "has_vba_macros": False,
        "has_xlm_macros": False,
        "macro_count": 0,
        "auto_exec_triggers": [],
        "suspicious_keywords": [],
        "iocs": [],
        "vmonkey_heuristics": [],
        "macro_snippets": []
    }
    
    if not OLETOOLS_AVAILABLE:
        result['error'] = "oletools not installed"
        return result
    
    try:
        vbaparser = VBA_Parser(file_path)
        
        if vbaparser.detect_vba_macros():
            result['has_vba_macros'] = True
            
            # Analyze macros
            for kw_type, kw_value, _ in vbaparser.analyze_macros():
                if kw_type == 'AutoExec':
                    result['auto_exec_triggers'].append(kw_value)
                elif kw_type == 'Suspicious':
                    result['suspicious_keywords'].append(kw_value)
                elif kw_type == 'IOC':
                    clean = kw_value.replace('"', '').replace("'", "").strip()
                    if clean:
                        score, verdict = score_link(clean)
                        result['iocs'].append({
                            "value": clean,
                            "verdict": verdict,
                            "score": score
                        })
            
            # Extract macro code for analysis
            all_code = ""
            for (_, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                result['macro_count'] += 1
                all_code += vba_code + "\n"
                
                # Store snippet
                if len(vba_code) > 50:
                    result['macro_snippets'].append({
                        "filename": vba_filename or stream_path or "Unknown",
                        "preview": vba_code[:200] + "..." if len(vba_code) > 200 else vba_code,
                        "hex_dump": hex_dump(vba_code.encode('utf-8', errors='ignore'), 32),
                        "length": len(vba_code)
                    })
            
            # VMonkey heuristic emulation
            if all_code:
                heuristics = heuristic_emulation(all_code)
                result['vmonkey_heuristics'] = heuristics
        
        # XLM macros
        if vbaparser.detect_xlm_macros():
            result['has_xlm_macros'] = True
        
        vbaparser.close()
    except Exception as e:
        result['error'] = str(e)
    
    return result


# ==========================================
# ZIP INTERNAL ANALYSIS
# ==========================================
def analyze_zip_internals(file_path: str) -> dict:
    """Analyze ZIP/OOXML internal structure"""
    result = {
        "encrypted_files": [],
        "suspicious_binaries": [],
        "part_count": 0,
        "parts": []
    }
    
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zf:
                for info in zf.infolist():
                    result['parts'].append({
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size
                    })
                    
                    # Encrypted file check
                    if info.flag_bits & 1:
                        result['encrypted_files'].append(info.filename)
                    
                    # Suspicious binaries
                    lower_name = info.filename.lower()
                    if lower_name.endswith(('.exe', '.bin', '.dll', '.vbs', '.js', '.ps1', '.bat', '.cmd')):
                        try:
                            data = zf.read(info.filename)
                            ent = shannon_entropy(data)
                            result['suspicious_binaries'].append({
                                "filename": info.filename,
                                "entropy": ent,
                                "hex_dump": hex_dump(data, 32),
                                "size": len(data)
                            })
                        except Exception:
                            result['suspicious_binaries'].append({
                                "filename": info.filename,
                                "note": "Could not read file"
                            })
                
                result['part_count'] = len(result['parts'])
    except Exception:
        pass
    
    return result


# ==========================================
# YARA SCANNING
# ==========================================
def scan_with_yara(file_path: str) -> list:
    """Scan file with YARA rules"""
    matches = []
    
    if not YARA_AVAILABLE:
        return matches
    
    try:
        rules = yara.compile(source='''
            rule Suspicious_OBF { strings: $a = "Chr" fullword ascii condition: #a > 10 }
            rule Suspicious_Shell { strings: $a = "Shell" fullword ascii condition: $a }
            rule Suspicious_PowerShell { strings: $a = "powershell" nocase condition: $a }
            rule Suspicious_WScript { strings: $a = "WScript.Shell" nocase condition: $a }
            rule Suspicious_Download { strings: $a = "URLDownloadToFile" nocase condition: $a }
        ''')
        hits = rules.match(file_path)
        for hit in hits:
            matches.append({
                "rule": hit.rule,
                "tags": list(hit.tags) if hit.tags else []
            })
    except Exception:
        pass
    
    return matches


# ==========================================
# MAIN ANALYSIS FUNCTION
# ==========================================
def get_comprehensive_office_analysis(file_path: str) -> dict:
    """
    Perform comprehensive Office document analysis
    Matches office.py output format
    """
    # Normalize the path
    file_path = os.path.normpath(file_path)
    
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}
    
    # 1. TrID File Identification
    type_name, magic = identify_file_type(file_path)
    
    # Check if it's an actual error reading the file
    if type_name.startswith("File Not Found") or type_name.startswith("Permission") or type_name.startswith("Read Error"):
        return {"error": f"Cannot read file: {type_name}"}
    
    # Check if supported - be more lenient, try to analyze OLE and ZIP even if signatures don't match perfectly
    is_ole = OLEFILE_AVAILABLE and olefile.isOleFile(file_path)
    is_zip = False
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            is_zip = True
    except:
        pass
    
    # If magic bytes indicate Office OR file structure is OLE/ZIP, proceed
    supported = type_name in SUPPORTED_OFFICE_TYPES or is_ole or is_zip
    
    if not supported:
        return {"error": f"Unsupported file type: {type_name}. Expected OLE or ZIP-based Office document."}
    
    # Adjust type name if needed
    if type_name not in SUPPORTED_OFFICE_TYPES:
        if is_ole:
            type_name = 'OLE Compound File (Legacy Office)'
        elif is_zip:
            type_name = 'ZIP Archive (OOXML/OpenDocument)'
    
    # 2. Build report (matching office.py structure)
    report = {
        "info": {
            "filename": os.path.basename(file_path),
            "trid_type": type_name,
            "magic": magic,
            "size": os.path.getsize(file_path),
            "hashes": calculate_hashes(file_path),
            "entropy": 0.0
        },
        "metadata": {},
        "reasons": [],
        "artifacts": [],
        "streams": [],
        "ole_map": {},
        "vmonkey_heuristics": [],
        "extracted_urls": [],
        "zip_internals": {},
        "macro_analysis": {},
        "yara_matches": [],
        "score": 0,
        "verdict": "SAFE"
    }
    
    # 3. Calculate entropy
    try:
        with open(file_path, 'rb') as f:
            report['info']['entropy'] = shannon_entropy(f.read())
    except Exception:
        pass
    
    # 4. Extract metadata
    report['metadata'] = extract_metadata(file_path, type_name)
    
    # 5. URL extraction
    report['extracted_urls'] = extract_all_urls(file_path)
    for u in report['extracted_urls']:
        if u['status'] == 'MALICIOUS':
            report['reasons'].append("Malicious Link Detected")
            break
    
    # 6. OLE Analysis (for legacy files)
    if "OLE Compound" in type_name:
        report['streams'] = analyze_oletimes(file_path)
        report['ole_map'] = analyze_sectors(file_path)
    
    # 7. Macro Analysis
    macro_result = analyze_macros(file_path)
    report['macro_analysis'] = macro_result
    
    if macro_result.get('has_vba_macros'):
        report['reasons'].append("VBA Macros Detected")
    
    if macro_result.get('has_xlm_macros'):
        report['reasons'].append("Legacy XLM Macros Found")
    
    if macro_result.get('auto_exec_triggers'):
        report['reasons'].append("Auto-Execution Trigger Found")
        for trigger in macro_result['auto_exec_triggers']:
            report['artifacts'].append({
                "type": "AutoExec Trigger",
                "value": trigger
            })
    
    if macro_result.get('vmonkey_heuristics'):
        report['vmonkey_heuristics'] = macro_result['vmonkey_heuristics']
        report['reasons'].append("Heuristic Obfuscation Detected")
    
    for ioc in macro_result.get('iocs', []):
        if ioc['verdict'] != 'SAFE':
            report['reasons'].append(f"Bad Link in Macro ({ioc['verdict']})")
            break
    
    for snippet in macro_result.get('macro_snippets', []):
        report['artifacts'].append({
            "type": "Macro Hex Dump",
            "value": f"{snippet['filename']}: {snippet['hex_dump']}"
        })
    
    # 8. ZIP Internals (for OOXML)
    if "ZIP" in type_name:
        report['zip_internals'] = analyze_zip_internals(file_path)
        
        if report['zip_internals'].get('encrypted_files'):
            report['reasons'].append("Internal Encrypted File")
            for ef in report['zip_internals']['encrypted_files']:
                report['artifacts'].append({
                    "type": "Encrypted File",
                    "value": ef
                })
        
        for sb in report['zip_internals'].get('suspicious_binaries', []):
            report['artifacts'].append({
                "type": "Suspicious Binary",
                "value": f"{sb['filename']} (Ent: {sb.get('entropy', 'N/A')}, Hex: {sb.get('hex_dump', 'N/A')})"
            })
    
    # 9. YARA Scanning
    report['yara_matches'] = scan_with_yara(file_path)
    if report['yara_matches']:
        report['reasons'].append("YARA Signature Match")
        for match in report['yara_matches']:
            report['artifacts'].append({
                "type": "YARA Match",
                "value": match['rule']
            })
    
    # 10. Calculate Score & Verdict
    score = 0
    reasons_str = str(report['reasons'])
    
    if "XLM" in reasons_str or "Malicious Link" in reasons_str:
        score = 10
    elif "Auto-Execution" in reasons_str or "YARA" in reasons_str:
        score = 9
    elif "Obfuscation" in reasons_str:
        score = 7
    elif "VBA" in reasons_str:
        score = 5
    elif "Encrypted" in reasons_str:
        score = 4
    
    report['score'] = score
    if score >= 8:
        report['verdict'] = "MALICIOUS"
    elif score >= 5:
        report['verdict'] = "SUSPICIOUS"
    else:
        report['verdict'] = "SAFE"
    
    return report


# Legacy function names for compatibility
def get_office_macro_analysis(file_path: str) -> dict:
    """Get macro analysis (compatibility wrapper)"""
    return analyze_macros(file_path)


def get_office_url_analysis(file_path: str) -> dict:
    """Get URL analysis (compatibility wrapper)"""
    urls = extract_all_urls(file_path)
    malicious_count = sum(1 for u in urls if u['status'] == 'MALICIOUS')
    suspicious_count = sum(1 for u in urls if u['status'] == 'SUSPICIOUS')
    
    return {
        "total_urls": len(urls),
        "malicious_urls": malicious_count,
        "suspicious_urls": suspicious_count,
        "safe_urls": len(urls) - malicious_count - suspicious_count,
        "urls": urls
    }
