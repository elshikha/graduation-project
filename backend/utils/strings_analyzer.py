"""
Strings Analysis Utility
Extracts and analyzes strings from binary files to identify indicators of compromise
Context-aware detection with classification to minimize false positives
"""

import os
import re
import subprocess
import requests
import base64
from collections import defaultdict

# External tools paths
STRINGS_EXE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'External', 'Strings', 'strings64.exe')

# Suspicious API calls commonly used by malware
SUSPICIOUS_APIS = [
    'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx', 'CreateRemoteThread',
    'WriteProcessMemory', 'ReadProcessMemory', 'OpenProcess', 'CreateProcess',
    'ShellExecute', 'WinExec', 'LoadLibrary', 'GetProcAddress',
    'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
    'CreateMutex', 'RegOpenKey', 'RegSetValue', 'RegDeleteKey',
    'InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'HttpSendRequest',
    'URLDownloadToFile', 'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
    'CreateService', 'StartService', 'DeleteService', 'OpenSCManager'
]

# Common DLL patterns that are suspicious
SUSPICIOUS_DLLS = [
    'ws2_32.dll', 'wininet.dll', 'urlmon.dll', 'advapi32.dll',
    'kernel32.dll', 'ntdll.dll', 'user32.dll', 'shell32.dll'
]

# EXECUTION COMMANDS - actual command-line executables
EXECUTION_COMMANDS = [
    'cmd.exe', 'cmd /c', 'command.com',
    'powershell.exe', 'pwsh.exe', 'powershell -',
    'wscript.exe', 'cscript.exe', 'mshta.exe',
    'bash', 'sh -c', '/bin/sh', '/bin/bash',
    'python.exe', 'python -c', 'perl -e'
]

# LOLBINS - Living Off the Land Binaries (legitimate tools abused by malware)
LOLBINS = [
    'certutil', 'bitsadmin', 'regsvr32', 'rundll32',
    'msiexec', 'installutil', 'regasm', 'regsvcs',
    'msxsl.exe', 'odbcconf', 'forfiles', 'pcalua'
]

# PERSISTENCE/SYSTEM COMMANDS - used for persistence or system manipulation
PERSISTENCE_COMMANDS = [
    'schtasks', 'sc.exe', 'sc ', 'at.exe',
    'reg add', 'reg delete', 'reg save',
    'netsh', 'wmic', 'net user', 'net localgroup',
    'vssadmin delete', 'wevtutil', 'bcdedit'
]

# NETWORK TOOLS - used for network operations
NETWORK_TOOLS = [
    'wget', 'curl', 'ftp.exe', 'tftp.exe',
    'net use', 'net share', 'nslookup', 'ping.exe'
]

# Go runtime patterns to IGNORE (not suspicious)
GO_RUNTIME_PATTERNS = [
    r'^runtime\.',
    r'^internal/',
    r'^encoding/',
    r'^syscall\.',
    r'^sync\.',
    r'^reflect\.',
    r'^fmt\.',
    r'^time\.',
    r'^io\.',
    r'^os\.',
    r'^net\.',
    r'^crypto/',
    r'panic',
    r'defer',
    r'malloc',
    r'gcwaiting',
    r'schedtick',
    r'profiling',
    r'GC sweep',
    r'goroutine',
    r'traceback'
]

# Windows system noise to IGNORE
WINDOWS_NOISE_PATTERNS = [
    r'Standard Time$',
    r'Daylight Time$',
    r'^\w+ \w+ Time$',  # Timezone names
    r'^bad defer',
    r'^cannot allocate',
    r'^invalid memory',
    r'^assertion failed',
    r'^\(Common Files\)',
    r'^Microsoft Corporation',
    r'^\d+\.\d+\.\d+\.\d+$'  # Version numbers only
]

# Command execution indicators
COMMAND_EXECUTION_PATTERNS = [
    r'(?:cmd|command)\s*/[ckq]',  # cmd /c or /k
    r'powershell(?:\.exe)?\s+-(?:enc|e|command|c|w\s+hidden)',  # PowerShell with flags
    r'(?:bash|sh)\s+-c',  # Bash execution
    r'&&|\|\||;(?:\s*\w+)',  # Command chaining
    r'(?:wget|curl)\s+(?:https?://|ftp://)',  # Network download
    r'certutil\s+(?:-decode|-urlcache)',  # Certutil abuse
    r'bitsadmin\s+/transfer',  # Bitsadmin download
    r'reg(?:\.exe)?\s+(?:add|delete|save)',  # Registry manipulation
    r'schtasks\s+/create',  # Scheduled task creation
    r'sc\s+(?:create|start|stop|delete)',  # Service manipulation
    r'net\s+(?:user|localgroup)\s+\w+\s+/add',  # User/group creation
    r'vssadmin\s+delete\s+shadows',  # Shadow copy deletion
    r'wevtutil\s+(?:cl|clear-log)',  # Event log clearing
    r'Invoke-(?:Expression|Command|WebRequest)',  # PowerShell invocation
    r'(?:DownloadFile|DownloadString)\s*\(',  # .NET WebClient
    r'IEX\s*\(',  # Invoke-Expression shorthand
    r'Start-Process\s+-',  # Process start
    r'mshta\s+(?:https?://|vbscript:)',  # Mshta abuse
    r'rundll32\s+\w+\.dll',  # DLL execution
    r'regsvr32\s+[/-]',  # Regsvr32 abuse
]


def is_noise_string(string):
    """
    Check if a string is runtime/debug noise that should be filtered out
    
    Args:
        string (str): String to check
        
    Returns:
        bool: True if string is noise and should be ignored
    """
    # Check Go runtime patterns
    for pattern in GO_RUNTIME_PATTERNS:
        if re.search(pattern, string, re.IGNORECASE):
            return True
    
    # Check Windows system noise
    for pattern in WINDOWS_NOISE_PATTERNS:
        if re.search(pattern, string):
            return True
    
    # Filter out pure debug/error templates
    if any(x in string.lower() for x in ['bad defer', 'panic:', 'traceback', 'assertion', 'cannot allocate']):
        return True
    
    return False


def is_binary_garbage(string):
    """
    Check if a string is binary garbage/noise that should not be analyzed as a command
    
    Args:
        string (str): String to check
        
    Returns:
        bool: True if string is likely binary garbage
    """
    # Too short to be a meaningful command (real commands are human-readable)
    if len(string) < 8:
        return True
    
    # Calculate printable ASCII ratio
    printable_count = sum(1 for c in string if c.isprintable() and c not in '\r\n\t')
    if len(string) > 0:
        printable_ratio = printable_count / len(string)
        if printable_ratio < 0.7:  # Less than 70% printable
            return True
    
    # Count special symbols vs alphanumeric
    symbol_count = sum(1 for c in string if c in '!@#$%^&*()_+{}[]|\\:;"<>?,./~`')
    alnum_count = sum(1 for c in string if c.isalnum())
    
    # If more symbols than alphanumeric characters, likely garbage
    if symbol_count > alnum_count:
        return True
    
    # Check for excessive consecutive symbols (e.g., |$@9;u)
    if re.search(r'[^\w\s]{4,}', string):  # 4+ non-word chars in a row
        return True
    
    # No spaces and very short with special chars (e.g., ;cpu.u, D$;dll)
    if ' ' not in string and len(string) < 15 and any(c in string for c in '$;|@[]{}'):
        # Check if it looks like assembly/binary artifact
        if re.search(r'^[a-zA-Z$_]+[;|@$]', string) or re.search(r'[;|@$][a-zA-Z$_]+$', string):
            return True
    
    return False


def has_execution_anchor(string):
    """
    Check if string contains a valid execution anchor (shell, interpreter, or LOLBin)
    
    Args:
        string (str): String to check
        
    Returns:
        tuple: (bool, str) - (has_anchor, anchor_found)
    """
    string_lower = string.lower()
    
    # Check for execution commands
    for cmd in EXECUTION_COMMANDS:
        if cmd.lower() in string_lower:
            # Verify with word boundary to avoid false matches
            if re.search(r'\b' + re.escape(cmd.lower().replace('.exe', '').replace(' -', '')) + r'\b', string_lower):
                return (True, cmd)
    
    # Check for LOLBins
    for lolbin in LOLBINS:
        if lolbin.lower() in string_lower:
            if re.search(r'\b' + re.escape(lolbin.lower()) + r'\b', string_lower):
                return (True, lolbin)
    
    # Check for persistence/system commands
    for cmd in PERSISTENCE_COMMANDS:
        # These are often phrases like "reg add" or "sc create"
        if cmd.lower() in string_lower:
            return (True, cmd)
    
    # Check for network tools
    for tool in NETWORK_TOOLS:
        if tool.lower() in string_lower:
            if re.search(r'\b' + re.escape(tool.lower().replace('.exe', '')) + r'\b', string_lower):
                return (True, tool)
    
    return (False, None)


def classify_string(string):
    """
    Classify a string into categories for context-aware analysis
    REQUIRES execution context before flagging as command
    
    Args:
        string (str): String to classify
        
    Returns:
        dict: Classification result with category, risk_level, and reason
    """
    # STAGE 1: Pre-filters - reject noise and garbage FIRST
    if is_noise_string(string):
        return {'category': 'NOISE', 'risk_level': 'NONE', 'reason': 'Runtime/debug string'}
    
    if is_binary_garbage(string):
        return {'category': 'BINARY_GARBAGE', 'risk_level': 'NONE', 'reason': 'Binary artifact or obfuscated data'}
    
    string_lower = string.lower()
    
    # STAGE 2: Check for execution anchor - REQUIRED for command classification
    has_anchor, anchor = has_execution_anchor(string)
    
    if not has_anchor:
        # No execution context - check for API references only
        for api in SUSPICIOUS_APIS:
            if api in string:
                return {
                    'category': 'API_REFERENCE',
                    'risk_level': 'MEDIUM',
                    'reason': f'Windows API reference: {api} (indicates capability, not execution)'
                }
        
        # No execution context and no API - not suspicious
        return {'category': 'NORMAL', 'risk_level': 'NONE', 'reason': 'No execution indicators'}
    
    # STAGE 3: Execution anchor found - now check for command patterns as SUPPORTING evidence
    risk_level = 'MEDIUM'  # Default for anchor presence
    reason = f'Execution utility present: {anchor}'
    category = 'EXECUTION_COMMAND'
    
    # Check for high-risk patterns (these elevate risk with anchor present)
    for pattern in COMMAND_EXECUTION_PATTERNS:
        if re.search(pattern, string, re.IGNORECASE):
            risk_level = 'HIGH'
            reason = f'Command execution: {anchor} with suspicious pattern'
            break
    
    # Check for encoded payloads with execution context
    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', string):
        risk_level = 'HIGH'
        reason = f'Encoded content with execution context: {anchor}'
        category = 'ENCODED_PAYLOAD'
    
    # Classify by anchor type for better granularity
    if anchor in LOLBINS:
        category = 'LOLBIN'
        risk_level = 'HIGH'
        reason = f'Living-off-the-land binary: {anchor}'
    elif any(cmd in anchor.lower() for cmd in ['schtasks', 'sc ', 'reg ', 'vssadmin', 'wevtutil', 'bcdedit']):
        category = 'PERSISTENCE_COMMAND'
        risk_level = 'HIGH'
        reason = f'Persistence/system manipulation: {anchor}'
    elif anchor in NETWORK_TOOLS:
        category = 'NETWORK_TOOL'
        risk_level = 'MEDIUM'
        reason = f'Network utility: {anchor}'
    
    return {
        'category': category,
        'risk_level': risk_level,
        'reason': reason
    }


def extract_strings(file_path, min_length=4):
    """
    Extract strings from binary file using strings.exe
    
    Args:
        file_path (str): Path to file
        min_length (int): Minimum string length to extract
        
    Returns:
        list: List of extracted strings
    """
    if not os.path.exists(STRINGS_EXE):
        return []
    
    try:
        # Run strings.exe with minimum length and no banner
        result = subprocess.run(
            [STRINGS_EXE, '-n', str(min_length), '-nobanner', file_path],
            capture_output=True,
            text=True,
            timeout=60,
            errors='ignore'
        )
        
        # Parse output - one string per line
        strings_list = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        return strings_list
        
    except subprocess.TimeoutExpired:
        return []
    except Exception as e:
        print(f"Error extracting strings: {e}")
        return []


def analyze_strings(file_path):
    """
    Analyze strings extracted from file to identify indicators
    
    Args:
        file_path (str): Path to file
        
    Returns:
        dict: Analysis results with indicators
    """
    # Check if strings.exe exists
    if not os.path.exists(STRINGS_EXE):
        return {'error': f'strings64.exe not found at {STRINGS_EXE}'}
    
    # Check if file exists
    if not os.path.exists(file_path):
        return {'error': f'File not found: {file_path}'}
    
    # Extract strings from file
    strings_list = extract_strings(file_path)
    
    if not strings_list:
        return {
            'total_strings': 0,
            'risk_score': 0,
            'risk_level': 'LOW',
            'indicators': {}
        }
    
    # Initialize results structure
    indicators = {
        'urls': [],
        'ip_addresses': [],
        'emails': [],
        'dll_files': [],
        'suspicious_apis': [],
        'registry_keys': [],
        'file_paths': [],
        'domains': [],
        'suspicious_commands': []
    }
    
    # Regex patterns
    url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    dll_pattern = re.compile(r'\b[\w-]+\.dll\b', re.IGNORECASE)
    # Domain pattern - only match valid domains with known TLDs (not ELF sections or Go packages)
    domain_pattern = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|edu|gov|mil|int|co|io|biz|info|name|pro|museum|aero|coop|xyz|online|site|tech|store|app|dev|cloud|live|me|tv|cc|in|uk|us|de|jp|fr|au|ca|cn|br|ru|nl|se|no|dk|fi|pl|it|es|be|ch|at|nz|sg|hk|kr|tw|th|my|id|ph|vn|za)\b', re.IGNORECASE)
    registry_pattern = re.compile(r'HKEY_[A-Z_]+\\[^\s\'"]+', re.IGNORECASE)
    file_path_pattern = re.compile(r'[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+', re.IGNORECASE)
    
    seen_urls = set()
    seen_ips = set()
    seen_emails = set()
    seen_dlls = set()
    seen_domains = set()
    seen_registry = set()
    seen_paths = set()
    seen_commands = set()
    
    for string in strings_list:
        # Extract URLs
        for match in url_pattern.finditer(string):
            url = match.group()
            if url not in seen_urls and len(seen_urls) < 20:
                seen_urls.add(url)
                indicators['urls'].append(url)
        
        # Extract IPs
        for match in ip_pattern.finditer(string):
            ip = match.group()
            # Filter out common local IPs
            if not ip.startswith(('127.', '0.', '255.')) and ip not in seen_ips and len(seen_ips) < 20:
                seen_ips.add(ip)
                indicators['ip_addresses'].append(ip)
        
        # Extract emails
        for match in email_pattern.finditer(string):
            email = match.group()
            if email not in seen_emails and len(seen_emails) < 10:
                seen_emails.add(email)
                indicators['emails'].append(email)
        
        # Extract DLLs
        for match in dll_pattern.finditer(string):
            dll = match.group().lower()
            if dll not in seen_dlls and len(seen_dlls) < 30:
                seen_dlls.add(dll)
                indicators['dll_files'].append(dll)
        
        # Extract domains (excluding those already in URLs, DLLs, and common false positives)
        for match in domain_pattern.finditer(string):
            domain = match.group().lower()
            # Exclude DLLs, ELF sections, Go packages, and other false positives
            if (len(domain) > 5 and 
                domain not in seen_domains and 
                not domain.endswith('.dll') and
                not any(domain in url for url in seen_urls) and 
                not domain.startswith(('b.', 'fmt.', 'os.', 'sys.', 'net.', 'io.', 'log.', 'flag.', 'poll.', 'time.', 'sync.', 'runtime.', 'unicode.', 'encoding.', 'crypto.', 'debug.', 'text.', 'html.')) and
                len(seen_domains) < 20):
                seen_domains.add(domain)
                indicators['domains'].append(domain)
        
        # Check for suspicious API calls
        for api in SUSPICIOUS_APIS:
            if api in string and api not in indicators['suspicious_apis'] and len(indicators['suspicious_apis']) < 20:
                indicators['suspicious_apis'].append(api)
        
        # Extract registry keys
        for match in registry_pattern.finditer(string):
            reg_key = match.group()
            if reg_key not in seen_registry and len(seen_registry) < 15:
                seen_registry.add(reg_key)
                indicators['registry_keys'].append(reg_key)
        
        # Extract file paths
        for match in file_path_pattern.finditer(string):
            path = match.group()
            if len(path) > 10 and path not in seen_paths and len(seen_paths) < 20:
                seen_paths.add(path)
                indicators['file_paths'].append(path)
        
        # NEW: Context-aware command detection with classification
        classification = classify_string(string)
        
        # Only add to suspicious_commands if it's actually executable
        if classification['risk_level'] in ['HIGH', 'CRITICAL'] and classification['category'] in [
            'EXECUTION_COMMAND', 'LOLBIN', 'PERSISTENCE_COMMAND', 'ENCODED_PAYLOAD'
        ]:
            if string not in seen_commands and len(seen_commands) < 15:
                seen_commands.add(string)
                # Store with classification metadata
                indicators['suspicious_commands'].append({
                    'string': string[:200],  # Limit context
                    'category': classification['category'],
                    'risk_level': classification['risk_level'],
                    'reason': classification['reason']
                })
    
    # Calculate risk score with updated weights
    risk_score = 0
    risk_score += len(indicators['urls']) * 2
    risk_score += len(indicators['ip_addresses']) * 3
    risk_score += len(indicators['suspicious_apis']) * 2
    risk_score += len(indicators['suspicious_commands']) * 5  # Higher weight for confirmed commands
    risk_score += len([dll for dll in indicators['dll_files'] if dll in SUSPICIOUS_DLLS]) * 2
    risk_score += len(indicators['registry_keys']) * 2
    risk_score += len(indicators['file_paths'])
    
    # Determine risk level
    if risk_score >= 30:
        risk_level = 'CRITICAL'
    elif risk_score >= 15:
        risk_level = 'HIGH'
    elif risk_score >= 7:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    return {
        'total_strings': len(strings_list),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'indicators': indicators
    }


def check_urls_with_virustotal(urls, api_key):
    """
    Check URLs against VirusTotal
    
    Args:
        urls (list): List of URLs to check
        api_key (str): VirusTotal API key
        
    Returns:
        dict: URL analysis results
    """
    results = {
        'checked': [],
        'malicious_count': 0
    }
    
    if not api_key or not urls:
        return results
    
    # Decode API key
    try:
        decoded_key = base64.b64decode(api_key).decode()
    except:
        decoded_key = api_key
    
    headers = {
        'x-apikey': decoded_key,
        'Accept': 'application/json'
    }
    
    base_url = 'https://www.virustotal.com/api/v3/urls'
    
    # Check first 5 URLs to avoid rate limiting
    for url in urls[:5]:
        try:
            # Encode URL for VT API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = requests.get(
                f'{base_url}/{url_id}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                
                url_result = {
                    'url': url,
                    'malicious_count': malicious,
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'undetected_count': stats.get('undetected', 0)
                }
                
                results['checked'].append(url_result)
                
                if malicious > 0:
                    results['malicious_count'] += 1
            
            # Small delay to respect rate limits
            import time
            time.sleep(1)
            
        except Exception as e:
            continue
    
    # Return just the list of checked URLs, not the wrapper dict
    return results['checked']
