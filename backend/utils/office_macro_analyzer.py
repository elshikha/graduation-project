"""
Office Macro Analyzer
Analyzes VBA macros and XLM macros in Office documents
Detects obfuscation patterns, auto-execution triggers, and suspicious behaviors
"""

import re
import binascii

# Try to import oletools
try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False
    print("[WARNING] oletools not installed. Macro analysis will be limited.")
    print("         Install with: pip install oletools")


# Obfuscation detection patterns
OBFUSCATION_PATTERNS = [
    (r'Chr\(\d+\)', 'Character Casting (Chr)'),
    (r'ChrW\(\d+\)', 'Unicode Casting (ChrW)'),
    (r'ChrB\(\d+\)', 'Byte Character Casting (ChrB)'),
    (r'StrReverse\(', 'String Reversal'),
    (r'[Bb]ase64', 'Base64 Encoding Reference'),
    (r'[Xx]or', 'XOR Operation'),
    (r'[Hh]ex\(', 'Hex Conversion'),
    (r'Replace\(.+,.+,.+\)', 'String Replacement'),
    (r'Split\(.+\)', 'String Splitting'),
    (r'Join\(.+\)', 'Array Joining'),
    (r'Mid\(.+\)', 'String Extraction (Mid)'),
    (r'Left\(.+\)', 'String Extraction (Left)'),
    (r'Right\(.+\)', 'String Extraction (Right)'),
    (r'Asc\(\w+\)', 'ASCII Conversion'),
    (r'Environ\(\s*["\'].+["\']\s*\)', 'Environment Variable Access'),
    (r'CallByName', 'Dynamic Function Call'),
    (r'ExecuteGlobal', 'Dynamic Code Execution'),
    (r'Eval\(', 'Eval Function'),
]

# Suspicious function patterns
SUSPICIOUS_FUNCTIONS = [
    (r'Shell\s*\(', 'Shell Command Execution'),
    (r'WScript\.Shell', 'WScript Shell Object'),
    (r'CreateObject\s*\(\s*["\']Wscript\.Shell["\']\s*\)', 'WScript Shell Creation'),
    (r'CreateObject\s*\(\s*["\']Shell\.Application["\']\s*\)', 'Shell Application Creation'),
    (r'CreateObject\s*\(\s*["\']Scripting\.FileSystemObject["\']\s*\)', 'FileSystem Access'),
    (r'CreateObject\s*\(\s*["\']MSXML2', 'HTTP Request Object'),
    (r'CreateObject\s*\(\s*["\']ADODB', 'Database/Stream Object'),
    (r'PowerShell', 'PowerShell Invocation'),
    (r'cmd\.exe|cmd\s*/c', 'Command Prompt Execution'),
    (r'certutil', 'Certutil Usage (Often for download)'),
    (r'bitsadmin', 'BITS Transfer'),
    (r'URLDownloadToFile', 'File Download'),
    (r'InternetOpen|HttpOpenRequest', 'WinINet API Usage'),
    (r'GetObject\s*\(', 'GetObject Call'),
    (r'\.Run\s*\(', 'Run Method'),
    (r'\.Exec\s*\(', 'Exec Method'),
    (r'RegWrite|RegRead|RegDelete', 'Registry Access'),
    (r'Kill\s+', 'File Deletion'),
    (r'Open\s+.+\s+For\s+Output', 'File Write Operation'),
    (r'Application\.MacroOptions', 'Macro Options Modification'),
]

# Auto-execution triggers
AUTO_EXEC_TRIGGERS = [
    'AutoOpen', 'AutoClose', 'AutoExec', 'AutoExit', 'AutoNew',
    'Document_Open', 'Document_Close', 'Document_New',
    'Workbook_Open', 'Workbook_Close', 'Workbook_Activate',
    'Worksheet_Activate', 'Worksheet_Change',
    'Auto_Open', 'Auto_Close', 'Auto_Activate',
    'Application_Start', 'Session_Start',
    'UserForm_Initialize', 'Class_Initialize'
]


def get_hex_dump(data: bytes, length: int = 64) -> str:
    """Convert bytes to formatted hex dump"""
    hex_str = binascii.hexlify(data[:length]).decode()
    return " ".join([hex_str[i:i+2].upper() for i in range(0, len(hex_str), 2)])


def detect_obfuscation(vba_code: str) -> list:
    """
    Detect obfuscation patterns in VBA code
    
    Args:
        vba_code (str): VBA source code
        
    Returns:
        list: Detected obfuscation patterns
    """
    detected = []
    
    for pattern, name in OBFUSCATION_PATTERNS:
        matches = re.findall(pattern, vba_code, re.IGNORECASE)
        if len(matches) > 3:  # Threshold for significance
            detected.append({
                "pattern": name,
                "count": len(matches),
                "severity": "high" if len(matches) > 10 else "medium"
            })
    
    return detected


def detect_suspicious_functions(vba_code: str) -> list:
    """
    Detect suspicious function calls in VBA code
    
    Args:
        vba_code (str): VBA source code
        
    Returns:
        list: Detected suspicious functions
    """
    detected = []
    
    for pattern, name in SUSPICIOUS_FUNCTIONS:
        matches = re.findall(pattern, vba_code, re.IGNORECASE)
        if matches:
            detected.append({
                "function": name,
                "count": len(matches),
                "severity": "critical" if 'Shell' in name or 'PowerShell' in name else "high"
            })
    
    return detected


def detect_auto_exec(vba_code: str) -> list:
    """
    Detect auto-execution triggers in VBA code
    
    Args:
        vba_code (str): VBA source code
        
    Returns:
        list: Detected auto-execution triggers
    """
    detected = []
    
    for trigger in AUTO_EXEC_TRIGGERS:
        pattern = rf'\b{trigger}\b'
        if re.search(pattern, vba_code, re.IGNORECASE):
            detected.append({
                "trigger": trigger,
                "severity": "critical"
            })
    
    return detected


def analyze_macros(file_path: str) -> dict:
    """
    Analyze VBA macros in Office document
    
    Args:
        file_path (str): Path to Office file
        
    Returns:
        dict: Macro analysis results
    """
    if not OLETOOLS_AVAILABLE:
        return {"error": "oletools not installed. Install with: pip install oletools"}
    
    result = {
        "has_vba_macros": False,
        "has_xlm_macros": False,
        "macro_count": 0,
        "macros": [],
        "auto_exec_triggers": [],
        "suspicious_functions": [],
        "obfuscation_patterns": [],
        "iocs": [],
        "artifacts": [],
        "risk_indicators": []
    }
    
    try:
        vbaparser = VBA_Parser(file_path)
        
        # Check for VBA macros
        if vbaparser.detect_vba_macros():
            result['has_vba_macros'] = True
            result['risk_indicators'].append("VBA Macros Detected")
            
            # Analyze macros
            for kw_type, kw_value, _ in vbaparser.analyze_macros():
                if kw_type == 'AutoExec':
                    result['auto_exec_triggers'].append({
                        "trigger": kw_value,
                        "type": "Auto-Execution",
                        "severity": "critical"
                    })
                    result['risk_indicators'].append(f"Auto-Execution Trigger: {kw_value}")
                    
                elif kw_type == 'Suspicious':
                    result['suspicious_functions'].append({
                        "function": kw_value,
                        "type": "Suspicious",
                        "severity": "high"
                    })
                    
                elif kw_type == 'IOC':
                    # Clean IOC value
                    clean_ioc = kw_value.replace('"', '').replace("'", "").strip()
                    if clean_ioc:
                        result['iocs'].append({
                            "value": clean_ioc,
                            "type": "IOC"
                        })
            
            # Extract and analyze macro code
            all_code = ""
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                result['macro_count'] += 1
                
                macro_info = {
                    "filename": vba_filename or "Unknown",
                    "stream_path": stream_path or "",
                    "code_length": len(vba_code),
                    "code_preview": vba_code[:500] if len(vba_code) > 500 else vba_code
                }
                
                # Add hex dump for substantial macros
                if len(vba_code) > 100:
                    macro_info['hex_dump'] = get_hex_dump(vba_code.encode('utf-8', errors='ignore'))
                
                result['macros'].append(macro_info)
                all_code += vba_code + "\n"
            
            # Run additional analysis on combined code
            if all_code:
                # Detect obfuscation
                obfuscation = detect_obfuscation(all_code)
                if obfuscation:
                    result['obfuscation_patterns'] = obfuscation
                    result['risk_indicators'].append("Obfuscation Patterns Detected")
                
                # Detect suspicious functions
                suspicious = detect_suspicious_functions(all_code)
                for func in suspicious:
                    if func not in result['suspicious_functions']:
                        result['suspicious_functions'].append(func)
                
                # Detect auto-exec triggers
                auto_exec = detect_auto_exec(all_code)
                for trigger in auto_exec:
                    exists = any(t['trigger'] == trigger['trigger'] for t in result['auto_exec_triggers'])
                    if not exists:
                        result['auto_exec_triggers'].append(trigger)
        
        # Check for XLM macros
        if vbaparser.detect_xlm_macros():
            result['has_xlm_macros'] = True
            result['risk_indicators'].append("Legacy XLM Macros Detected (High Risk)")
        
        vbaparser.close()
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def get_office_macro_analysis(file_path: str) -> dict:
    """
    Get comprehensive macro analysis for Office document
    
    Args:
        file_path (str): Path to Office file
        
    Returns:
        dict: Complete macro analysis with risk assessment
    """
    analysis = analyze_macros(file_path)
    
    if 'error' in analysis:
        return analysis
    
    # Calculate macro risk score
    risk_score = 0
    
    # VBA macros base score
    if analysis['has_vba_macros']:
        risk_score += 2
    
    # XLM macros (legacy, often malicious)
    if analysis['has_xlm_macros']:
        risk_score += 4
    
    # Auto-execution triggers
    risk_score += len(analysis['auto_exec_triggers']) * 2
    
    # Suspicious functions
    for func in analysis['suspicious_functions']:
        if func.get('severity') == 'critical':
            risk_score += 2
        else:
            risk_score += 1
    
    # Obfuscation patterns
    for pattern in analysis['obfuscation_patterns']:
        if pattern.get('severity') == 'high':
            risk_score += 2
        else:
            risk_score += 1
    
    # IOCs
    risk_score += len(analysis['iocs']) * 0.5
    
    # Normalize score
    analysis['macro_risk_score'] = min(10, round(risk_score, 1))
    
    # Determine macro status
    if risk_score >= 8:
        analysis['macro_status'] = "MALICIOUS"
        analysis['macro_status_color'] = "red"
    elif risk_score >= 5:
        analysis['macro_status'] = "SUSPICIOUS"
        analysis['macro_status_color'] = "orange"
    elif analysis['has_vba_macros'] or analysis['has_xlm_macros']:
        analysis['macro_status'] = "PRESENT"
        analysis['macro_status_color'] = "yellow"
    else:
        analysis['macro_status'] = "CLEAN"
        analysis['macro_status_color'] = "green"
    
    return analysis
