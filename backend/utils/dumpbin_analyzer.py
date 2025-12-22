"""
Dumpbin PE Structure Analyzer
Uses Microsoft dumpbin.exe to perform static structural analysis of PE files
"""

import os
import subprocess
import re
import pefile
import datetime
import math
from collections import Counter


def get_dumpbin_path():
    """Get the path to dumpbin.exe in the External folder"""
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        'External', 'dumpbin', 'dumpbin.exe'
    )


def run_dumpbin(file_path, option):
    """
    Run dumpbin with specified option
    
    Args:
        file_path (str): Path to PE file
        option (str): Dumpbin option (/imports, /exports, /headers)
        
    Returns:
        str: Raw output from dumpbin
    """
    dumpbin_exe = get_dumpbin_path()
    
    if not os.path.exists(dumpbin_exe):
        return None
    
    if not os.path.exists(file_path):
        return None
    
    abs_file_path = os.path.abspath(file_path)
    
    try:
        result = subprocess.run(
            [dumpbin_exe, option, abs_file_path],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(dumpbin_exe)
        )
        
        return result.stdout
        
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        print(f"Dumpbin error: {e}")
        return None


def parse_imports(imports_output):
    """
    Parse dumpbin /imports output
    
    Returns:
        dict: Parsed imports data with analysis
    """
    if not imports_output:
        return {'error': 'No imports output'}
    
    imports = {}
    current_dll = None
    
    lines = imports_output.split('\n')
    
    for line in lines:
        # Detect DLL name (indented, ends with .dll)
        if line.strip().endswith('.dll'):
            current_dll = line.strip()
            imports[current_dll] = []
        # Detect imported function (starts with spaces and a number)
        elif current_dll and re.match(r'^\s+\d+\s+\w+', line):
            func_name = line.strip().split()[-1]
            imports[current_dll].append(func_name)
    
    # Analyze imports for security implications
    analysis = analyze_imports(imports)
    
    return {
        'imports': imports,
        'dll_count': len(imports),
        'total_functions': sum(len(funcs) for funcs in imports.values()),
        'analysis': analysis
    }


def analyze_imports(imports):
    """
    Analyze imports for security implications
    
    Returns:
        dict: Analysis findings
    """
    findings = []
    risk_indicators = []
    
    all_functions = []
    for dll, funcs in imports.items():
        all_functions.extend(funcs)
    
    # Check for minimal imports (packing indicator)
    if len(imports) <= 2 and 'kernel32.dll' in imports:
        findings.append({
            'category': 'Minimal Imports',
            'severity': 'HIGH',
            'description': 'The binary imports only a minimal set of libraries (kernel32.dll). This is a strong indicator of packing or runtime API resolution, where the true imports are hidden and resolved dynamically at runtime.'
        })
        risk_indicators.append('MINIMAL_IMPORTS')
    
    # Check for dynamic API resolution
    dynamic_api_funcs = ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress']
    found_dynamic = [f for f in all_functions if f in dynamic_api_funcs]
    if found_dynamic:
        findings.append({
            'category': 'Dynamic API Resolution',
            'severity': 'HIGH',
            'description': f'Functions detected: {", ".join(found_dynamic)}. The binary is likely resolving APIs dynamically at runtime to hide its true behavior from static analysis. This is a common technique used by malware to evade detection and complicate reverse engineering.'
        })
        risk_indicators.append('DYNAMIC_API_RESOLUTION')
    
    # Check for memory manipulation
    memory_funcs = ['VirtualAlloc', 'VirtualAllocEx', 'VirtualFree', 'VirtualProtect', 'VirtualProtectEx', 
                    'VirtualQuery', 'VirtualQueryEx', 'WriteProcessMemory', 'ReadProcessMemory']
    found_memory = [f for f in all_functions if f in memory_funcs]
    if found_memory:
        findings.append({
            'category': 'Memory Manipulation',
            'severity': 'HIGH',
            'description': f'Functions detected: {", ".join(found_memory)}. These APIs are commonly used for unpacking, shellcode staging, in-memory execution, or process injection. The binary can allocate executable memory dynamically, which is typical behavior for loaders, injectors, and packed malware.'
        })
        risk_indicators.append('MEMORY_MANIPULATION')
    
    # Check for thread manipulation
    thread_funcs = ['CreateThread', 'CreateRemoteThread', 'SuspendThread', 'ResumeThread', 
                    'GetThreadContext', 'SetThreadContext', 'TerminateThread', 'QueueUserAPC']
    found_thread = [f for f in all_functions if f in thread_funcs]
    if found_thread:
        findings.append({
            'category': 'Thread Manipulation',
            'severity': 'HIGH',
            'description': f'Functions detected: {", ".join(found_thread)}. These APIs are typical of loaders, injectors, and anti-analysis techniques. The ability to manipulate thread context suggests process hollowing, thread hijacking, or APC injection capabilities.'
        })
        risk_indicators.append('THREAD_MANIPULATION')
    
    # Check for exception handling (anti-debugging)
    exception_funcs = ['AddVectoredExceptionHandler', 'RemoveVectoredExceptionHandler', 
                       'SetUnhandledExceptionFilter', 'RaiseException']
    found_exception = [f for f in all_functions if f in exception_funcs]
    if found_exception:
        findings.append({
            'category': 'Exception Handling',
            'severity': 'MEDIUM',
            'description': f'Functions detected: {", ".join(found_exception)}. These APIs are commonly used in packers, control-flow obfuscation, and anti-debugging logic. Exception handlers can be used to detect debuggers, hide malicious code flow, or implement anti-analysis techniques.'
        })
        risk_indicators.append('EXCEPTION_HANDLING')
    
    # Check for process manipulation
    process_funcs = ['CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserA', 'CreateProcessAsUserW',
                     'OpenProcess', 'TerminateProcess']
    found_process = [f for f in all_functions if f in process_funcs]
    if found_process:
        findings.append({
            'category': 'Process Manipulation',
            'severity': 'MEDIUM',
            'description': f'Functions detected: {", ".join(found_process)}. The binary can create or manipulate other processes, which may indicate injection, spawning of additional payloads, or lateral movement capabilities.'
        })
        risk_indicators.append('PROCESS_MANIPULATION')
    
    # Calculate weighted risk score (max 35 points out of 100)
    risk_weights = {
        'MINIMAL_IMPORTS': 8,
        'DYNAMIC_API_RESOLUTION': 10,
        'MEMORY_MANIPULATION': 8,
        'THREAD_MANIPULATION': 5,
        'EXCEPTION_HANDLING': 2,
        'PROCESS_MANIPULATION': 2
    }
    risk_score = sum(risk_weights.get(indicator, 5) for indicator in risk_indicators)
    risk_score = min(risk_score, 35)  # Cap at 35
    
    return {
        'findings': findings,
        'risk_indicators': risk_indicators,
        'risk_score': risk_score
    }


def parse_exports(exports_output):
    """
    Parse dumpbin /exports output
    
    Returns:
        dict: Parsed exports data with analysis
    """
    if not exports_output:
        return {'error': 'No exports output'}
    
    exports = []
    
    # Check if exports section exists
    has_exports = 'ordinal hint RVA' in exports_output or 'ordinal' in exports_output.lower()
    
    if not has_exports:
        return {
            'exports': [],
            'export_count': 0,
            'analysis': {
                'description': 'No exported functions detected. This is normal behavior for an executable file (.exe). Executables typically do not export functions as they are entry-point programs, not libraries.',
                'severity': 'INFO'
            }
        }
    
    # Parse exported functions if present
    lines = exports_output.split('\n')
    for line in lines:
        if re.match(r'^\s+\d+\s+\d+\s+[0-9A-F]+\s+\w+', line, re.IGNORECASE):
            parts = line.strip().split()
            if len(parts) >= 4:
                exports.append(parts[3])
    
    return {
        'exports': exports,
        'export_count': len(exports),
        'analysis': {
            'description': f'{len(exports)} exported function(s) detected. This may indicate a DLL-style payload, plugin architecture, or potential DLL sideloading behavior. Executables with exports are uncommon and may suggest the binary is designed to be loaded by another process or framework.',
            'severity': 'MEDIUM'
        }
    }


def parse_headers(headers_output):
    """
    Parse dumpbin /headers output for section information
    
    Returns:
        dict: Parsed section data with permissions analysis
    """
    if not headers_output:
        return {'error': 'No headers output'}
    
    sections = []
    current_section = None
    
    lines = headers_output.split('\n')
    
    for i, line in enumerate(lines):
        # Detect section header
        if 'SECTION HEADER' in line:
            if current_section:
                sections.append(current_section)
            current_section = {}
        
        elif current_section is not None:
            # Parse section name
            if 'name' in line and 'virtual size' not in line:
                current_section['name'] = line.split('name')[0].strip()
            
            # Parse virtual size
            elif 'virtual size' in line:
                match = re.search(r'([0-9A-F]+)\s+virtual size', line, re.IGNORECASE)
                if match:
                    current_section['virtual_size'] = match.group(1)
            
            # Parse flags and permissions
            elif 'flags' in line.lower():
                flags_line = line.strip()
                current_section['flags'] = flags_line
                
                # Parse subsequent lines for permission flags
                permissions = []
                j = i + 1
                while j < len(lines) and lines[j].strip() and 'SECTION HEADER' not in lines[j]:
                    flag_text = lines[j].strip()
                    if flag_text and not re.match(r'^[0-9A-F]+', flag_text):
                        permissions.append(flag_text)
                    j += 1
                
                current_section['permission_flags'] = permissions
                current_section['permissions'] = interpret_permissions(permissions)
    
    # Add last section
    if current_section:
        sections.append(current_section)
    
    # Analyze sections
    analysis = analyze_sections(sections)
    
    return {
        'sections': sections,
        'section_count': len(sections),
        'analysis': analysis
    }


def interpret_permissions(permission_flags):
    """
    Interpret dumpbin permission flags into readable format (R/W/X)
    
    Returns:
        str: Permission string (e.g., 'RX', 'RW', 'R')
    """
    perms = []
    
    flags_text = ' '.join(permission_flags).lower()
    
    if 'execute' in flags_text or 'code' in flags_text:
        perms.append('X')
    if 'write' in flags_text:
        perms.append('W')
    if 'read' in flags_text or 'initialized data' in flags_text:
        perms.append('R')
    
    if not perms:
        perms.append('R')  # Default to read-only
    
    # Order: RWX
    result = ''
    if 'R' in perms:
        result += 'R'
    if 'W' in perms:
        result += 'W'
    if 'X' in perms:
        result += 'X'
    
    return result if result else 'R'


def analyze_sections(sections):
    """
    Analyze PE sections for anomalies
    
    Returns:
        dict: Analysis findings
    """
    findings = []
    risk_indicators = []
    
    # Check for RWX sections
    rwx_sections = [s for s in sections if s.get('permissions') == 'RWX']
    if rwx_sections:
        findings.append({
            'category': 'Executable Writable Section',
            'severity': 'CRITICAL',
            'description': f'Section(s) {", ".join(s["name"] for s in rwx_sections)} are both writable and executable (RWX). This is highly suspicious and indicates potential shellcode staging, self-modifying code, or runtime code generation. This configuration is rarely seen in legitimate software.',
            'sections': [s['name'] for s in rwx_sections]
        })
        risk_indicators.append('RWX_SECTION')
    
    # Check for unusual section names
    normal_sections = ['.text', '.rdata', '.data', '.rsrc', '.reloc', '.idata', '.edata', '.pdata', '.tls']
    unusual = [s for s in sections if s.get('name') not in normal_sections]
    if unusual:
        findings.append({
            'category': 'Unusual Section Names',
            'severity': 'MEDIUM',
            'description': f'Non-standard section names detected: {", ".join(s["name"] for s in unusual)}. Custom section names may indicate custom toolchains, packers, or malware frameworks. The .symtab section is particularly unusual for production binaries.',
            'sections': [s['name'] for s in unusual]
        })
        risk_indicators.append('UNUSUAL_SECTIONS')
    
    # Check for large .data section
    data_section = next((s for s in sections if s.get('name') == '.data'), None)
    if data_section:
        try:
            data_size = int(data_section.get('virtual_size', '0'), 16)
            if data_size > 0x100000:  # >1MB
                findings.append({
                    'category': 'Unusually Large .data Section',
                    'severity': 'MEDIUM',
                    'description': f'The .data section is unusually large ({data_size / 1024 / 1024:.2f} MB). This may indicate embedded payloads, compressed data, or resources hidden in the data section.',
                    'size': data_size
                })
                risk_indicators.append('LARGE_DATA_SECTION')
        except:
            pass
    
    # Summary based on normal layout
    normal_layout = {
        '.text': 'RX',
        '.rdata': 'R',
        '.data': 'RW',
        '.rsrc': 'R'
    }
    
    layout_description = 'Normal PE layout: .text (RX - executable code), .rdata (R - read-only data), .data (RW - initialized variables), .rsrc (R - resources).'
    
    if not rwx_sections:
        findings.append({
            'category': 'Section Layout',
            'severity': 'INFO',
            'description': f'{layout_description} No statically writable and executable sections detected. However, malware often avoids RWX sections and instead allocates executable memory dynamically at runtime using VirtualAlloc or similar APIs.',
        })
    
    # Calculate weighted risk score (max 30 points out of 100)
    risk_weights = {
        'RWX_SECTION': 25,
        'UNUSUAL_SECTIONS': 3,
        'LARGE_DATA_SECTION': 2
    }
    risk_score = sum(risk_weights.get(indicator, 3) for indicator in risk_indicators)
    risk_score = min(risk_score, 30)  # Cap at 30
    
    return {
        'findings': findings,
        'risk_indicators': risk_indicators,
        'risk_score': risk_score
    }


def calculate_entropy(data):
    """
    Calculate Shannon entropy of byte data
    Higher entropy (closer to 8) indicates encryption/compression
    
    Returns:
        float: Entropy value (0-8)
    """
    if not data:
        return 0.0
    
    entropy = 0
    counter = Counter(data)
    length = len(data)
    
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def analyze_resources(file_path):
    """
    Analyze PE resources using pefile library
    
    Returns:
        dict: Resource analysis findings
    """
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {'error': f'Failed to parse PE file: {str(e)}'}
    
    findings = []
    risk_indicators = []
    resources_summary = []
    
    # Check if resource directory exists
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return {
            'resources': [],
            'resource_count': 0,
            'analysis': {
                'description': 'No resource directory found in this PE file. This is somewhat unusual for Windows executables, as most legitimate software includes at least icons or version information. The absence of resources may indicate a stripped binary, custom packer, or non-standard toolchain.',
                'severity': 'MEDIUM'
            },
            'findings': findings,
            'risk_indicators': risk_indicators
        }
    
    # Resource type mapping (numeric ID to name)
    resource_types = {
        1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU',
        5: 'RT_DIALOG', 6: 'RT_STRING', 7: 'RT_FONTDIR', 8: 'RT_FONT',
        9: 'RT_ACCELERATOR', 10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE',
        12: 'RT_GROUP_CURSOR', 14: 'RT_GROUP_ICON', 16: 'RT_VERSION',
        17: 'RT_DLGINCLUDE', 19: 'RT_PLUGPLAY', 20: 'RT_VXD',
        21: 'RT_ANICURSOR', 22: 'RT_ANIICON', 23: 'RT_HTML',
        24: 'RT_MANIFEST'
    }
    
    rcdata_found = False
    embedded_pe_found = False
    suspicious_scripts_found = []
    high_entropy_resources = []
    
    # Iterate through resource entries
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        # Get resource type name
        if resource_type.id in resource_types:
            type_name = resource_types[resource_type.id]
        elif hasattr(resource_type, 'name') and resource_type.name:
            type_name = str(resource_type.name)
        else:
            type_name = f'CUSTOM_TYPE_{resource_type.id}'
        
        # Count resources of this type
        resource_count = 0
        if hasattr(resource_type, 'directory'):
            for resource_id in resource_type.directory.entries:
                if hasattr(resource_id, 'directory'):
                    for resource_lang in resource_id.directory.entries:
                        resource_count += 1
                        
                        # Extract resource data for analysis
                        try:
                            data_rva = resource_lang.data.struct.OffsetToData
                            size = resource_lang.data.struct.Size
                            data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                            
                            # Check for embedded PE (MZ header)
                            if len(data) > 2 and data[:2] == b'MZ':
                                embedded_pe_found = True
                                findings.append({
                                    'category': 'Embedded PE File in Resources',
                                    'severity': 'HIGH',
                                    'description': f'An embedded PE executable was detected in {type_name} resource (size: {size} bytes). This is a strong indicator of a dropper, loader, or staged execution model. Malware frequently embeds secondary payloads, DLLs, or shellcode loaders in resources to evade detection and deliver additional components at runtime.',
                                    'resource_type': type_name,
                                    'size': size
                                })
                                risk_indicators.append('EMBEDDED_PE')
                            
                            # Check for script strings (PowerShell, JavaScript, batch)
                            if size > 10:
                                text_sample = data[:min(2048, size)].decode('utf-8', errors='ignore').lower()
                                script_keywords = {
                                    'PowerShell': ['powershell', 'invoke-expression', 'downloadstring', 'new-object', 'system.net.webclient'],
                                    'JavaScript': ['<script', 'eval(', 'wscript.', 'activexobject'],
                                    'Batch': ['@echo off', 'cmd.exe', 'call ', 'goto ', 'if exist']
                                }
                                
                                for script_type, keywords in script_keywords.items():
                                    if any(kw in text_sample for kw in keywords):
                                        if script_type not in suspicious_scripts_found:
                                            suspicious_scripts_found.append(script_type)
                            
                            # Check for high entropy (encryption/compression)
                            if size > 256:
                                entropy = calculate_entropy(data)
                                if entropy > 7.0:  # High entropy threshold
                                    high_entropy_resources.append({
                                        'type': type_name,
                                        'size': size,
                                        'entropy': entropy
                                    })
                        
                        except Exception:
                            pass  # Skip resources that can't be extracted
        
        resources_summary.append({
            'type': type_name,
            'count': resource_count
        })
        
        # Flag RT_RCDATA as suspicious
        if type_name == 'RT_RCDATA':
            rcdata_found = True
    
    # Generate findings based on analysis
    if rcdata_found:
        findings.append({
            'category': 'RT_RCDATA Resources Present',
            'severity': 'MEDIUM',
            'description': 'The binary contains RT_RCDATA (raw data) resources. This resource type is frequently abused by malware to store encrypted payloads, shellcode, configuration data, or secondary executables. While legitimate software can use RT_RCDATA, its presence warrants inspection, especially when combined with minimal imports or dynamic API resolution.',
        })
        risk_indicators.append('RCDATA_PRESENT')
    
    if suspicious_scripts_found:
        findings.append({
            'category': 'Script Content in Resources',
            'severity': 'HIGH',
            'description': f'Suspicious script content detected in resources: {", ".join(suspicious_scripts_found)}. Resources containing scripts suggest the binary may execute external commands, download additional payloads, or leverage scripting engines for evasion. This is common in droppers and loaders.',
            'script_types': suspicious_scripts_found
        })
        risk_indicators.append('SCRIPT_IN_RESOURCES')
    
    if high_entropy_resources:
        findings.append({
            'category': 'High-Entropy Resources',
            'severity': 'MEDIUM',
            'description': f'{len(high_entropy_resources)} resource(s) with high entropy (>7.0) detected. High entropy indicates encrypted or compressed data, which is typical of packed malware. Legitimate compressed resources (like icons) usually have moderate entropy, whereas malware payloads exhibit near-random byte distributions.',
            'resources': high_entropy_resources
        })
        risk_indicators.append('HIGH_ENTROPY_RESOURCES')
    
    # Calculate weighted risk score (max 25 points out of 100)
    risk_weights = {
        'EMBEDDED_PE': 15,
        'SCRIPT_IN_RESOURCES': 8,
        'HIGH_ENTROPY_RESOURCES': 5,
        'RCDATA_PRESENT': 2
    }
    risk_score = sum(risk_weights.get(indicator, 3) for indicator in risk_indicators)
    risk_score = min(risk_score, 25)  # Cap at 25
    
    pe.close()
    
    return {
        'resources': resources_summary,
        'resource_count': len(resources_summary),
        'analysis': {
            'description': f'{len(resources_summary)} resource type(s) found. Resources can contain legitimate application data (icons, version info, manifests) or malicious payloads (embedded executables, scripts, encrypted data).',
            'severity': 'INFO'
        },
        'findings': findings,
        'risk_indicators': risk_indicators,
        'risk_score': risk_score
    }


def analyze_timestamps(file_path):
    """
    Analyze PE timestamps and digital signature using pefile library
    
    Returns:
        dict: Timestamp analysis findings
    """
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {'error': f'Failed to parse PE file: {str(e)}'}
    
    findings = []
    risk_indicators = []
    
    # Extract compilation timestamp
    timestamp_raw = pe.FILE_HEADER.TimeDateStamp
    
    # Check for suspicious timestamp values
    timestamp_suspicious = False
    timestamp_explanation = ''
    
    if timestamp_raw == 0:
        timestamp_suspicious = True
        timestamp_explanation = 'The compilation timestamp is set to zero (null timestamp). This is a common anti-forensic technique used by malware packers to remove build metadata and hinder timeline analysis. Legitimate compilers always set a valid timestamp.'
    elif timestamp_raw == 0xFFFFFFFF or timestamp_raw > 0x7FFFFFFF:
        timestamp_suspicious = True
        timestamp_explanation = 'The compilation timestamp contains an invalid or maximum value. This indicates intentional timestamp manipulation to evade forensic analysis and remove temporal indicators.'
    else:
        try:
            compile_time = datetime.datetime.utcfromtimestamp(timestamp_raw)
            current_time = datetime.datetime.utcnow()
            
            # Check if timestamp is in the future
            if compile_time > current_time:
                timestamp_suspicious = True
                timestamp_explanation = f'The compilation timestamp is set to a future date ({compile_time.strftime("%Y-%m-%d %H:%M:%S UTC")}). This is impossible and indicates timestamp manipulation, a common anti-forensic technique used by malware to complicate analysis.'
            # Check if timestamp is unrealistically old (before Windows 95 release)
            elif compile_time.year < 1995:
                timestamp_suspicious = True
                timestamp_explanation = f'The compilation timestamp ({compile_time.strftime("%Y-%m-%d %H:%M:%S UTC")}) predates modern Windows operating systems. This is likely a manipulated or invalid timestamp rather than a genuine build date.'
            # Check for Unix epoch
            elif timestamp_raw <= 86400:  # Within 1 day of epoch
                timestamp_suspicious = True
                timestamp_explanation = f'The compilation timestamp is set to the Unix epoch ({compile_time.strftime("%Y-%m-%d %H:%M:%S UTC")}). This is a clear indicator of timestamp wiping, commonly performed by malware packers to remove forensic artifacts.'
            else:
                timestamp_explanation = f'The compilation timestamp is {compile_time.strftime("%Y-%m-%d %H:%M:%S UTC")}. This appears to be a valid timestamp, though it should be correlated with other indicators. Malware can set realistic timestamps to appear legitimate.'
        except:
            timestamp_suspicious = True
            timestamp_explanation = 'The compilation timestamp could not be converted to a valid date. This indicates corruption or intentional manipulation.'
    
    if timestamp_suspicious:
        findings.append({
            'category': 'Suspicious Compilation Timestamp',
            'severity': 'MEDIUM',
            'description': timestamp_explanation,
            'timestamp_raw': timestamp_raw
        })
        risk_indicators.append('SUSPICIOUS_TIMESTAMP')
    else:
        findings.append({
            'category': 'Compilation Timestamp',
            'severity': 'INFO',
            'description': timestamp_explanation,
            'timestamp_raw': timestamp_raw
        })
    
    # Check for digital signature
    signature_present = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY
    
    if not signature_present:
        findings.append({
            'category': 'No Digital Signature',
            'severity': 'MEDIUM',
            'description': 'The binary is not digitally signed. While unsigned binaries are not inherently malicious, the absence of a signature is common in malware and makes origin verification impossible. Legitimate commercial software is typically signed to establish trust and verify publisher identity.',
        })
        risk_indicators.append('UNSIGNED_BINARY')
    else:
        findings.append({
            'category': 'Digital Signature Present',
            'severity': 'INFO',
            'description': 'The binary contains a digital signature in its Security Directory. The presence of a signature suggests the binary was signed by a publisher, though the validity and trustworthiness of the certificate must be verified separately. Stolen or expired certificates are sometimes used by malware.',
        })
    
    # Calculate weighted risk score (max 10 points out of 100)
    risk_weights = {
        'SUSPICIOUS_TIMESTAMP': 4,
        'UNSIGNED_BINARY': 6
    }
    risk_score = sum(risk_weights.get(indicator, 3) for indicator in risk_indicators)
    risk_score = min(risk_score, 10)  # Cap at 10
    
    pe.close()
    
    return {
        'timestamp': timestamp_raw,
        'signed': signature_present,
        'findings': findings,
        'risk_indicators': risk_indicators,
        'risk_score': risk_score
    }


def analyze_overlays(file_path):
    """
    Detect and analyze overlay data (bytes after last section) using pefile
    
    Returns:
        dict: Overlay analysis findings
    """
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {'error': f'Failed to parse PE file: {str(e)}'}
    
    findings = []
    risk_indicators = []
    overlay_data = None
    overlay_size = 0
    
    # Get overlay data (data after last section)
    overlay_offset = pe.get_overlay_data_start_offset()
    
    if overlay_offset is not None:
        # Read overlay data
        with open(file_path, 'rb') as f:
            f.seek(overlay_offset)
            overlay_data = f.read()
            overlay_size = len(overlay_data)
        
        if overlay_size > 0:
            findings.append({
                'category': 'Overlay Data Detected',
                'severity': 'MEDIUM',
                'description': f'The binary contains {overlay_size} bytes ({overlay_size / 1024:.2f} KB) of overlay data appended after the last PE section. Overlay data is not mapped into memory during normal execution and is often used by malware to store encrypted payloads, configuration data, or secondary executables that are extracted and executed at runtime.',
                'size': overlay_size
            })
            risk_indicators.append('OVERLAY_PRESENT')
            
            # Check if overlay starts with MZ header (embedded PE)
            if overlay_size > 2 and overlay_data[:2] == b'MZ':
                findings.append({
                    'category': 'Embedded PE in Overlay',
                    'severity': 'HIGH',
                    'description': f'The overlay data begins with an MZ header, indicating an embedded PE executable ({overlay_size / 1024:.2f} KB). This is a strong indicator of a dropper or loader that extracts and executes a secondary payload at runtime. Malware commonly uses this technique to evade static detection by hiding the true malicious payload in the overlay.',
                    'size': overlay_size
                })
                risk_indicators.append('PE_IN_OVERLAY')
            
            # Check for high entropy (encryption/compression)
            elif overlay_size > 256:
                entropy = calculate_entropy(overlay_data[:min(10240, overlay_size)])  # Sample first 10KB
                if entropy > 7.0:
                    findings.append({
                        'category': 'High-Entropy Overlay Data',
                        'severity': 'HIGH',
                        'description': f'The overlay data exhibits high entropy ({entropy:.2f}/8.0), indicating it is likely encrypted or compressed. This is typical of packed malware where the overlay contains an encrypted payload that is decrypted and executed at runtime. The presence of high-entropy overlay data strongly suggests hidden malicious functionality.',
                        'entropy': entropy,
                        'size': overlay_size
                    })
                    risk_indicators.append('ENCRYPTED_OVERLAY')
            
            # Check for script indicators
            if overlay_size > 10:
                text_sample = overlay_data[:min(2048, overlay_size)].decode('utf-8', errors='ignore').lower()
                script_keywords = {
                    'PowerShell': ['powershell', 'invoke-expression', 'iex', 'downloadstring', 'webclient'],
                    'Batch': ['@echo off', 'cmd.exe', 'start /b'],
                    'VBScript': ['wscript', 'createobject', 'execute']
                }
                
                found_scripts = []
                for script_type, keywords in script_keywords.items():
                    if any(kw in text_sample for kw in keywords):
                        found_scripts.append(script_type)
                
                if found_scripts:
                    findings.append({
                        'category': 'Script Content in Overlay',
                        'severity': 'HIGH',
                        'description': f'The overlay contains embedded script content: {", ".join(found_scripts)}. This suggests the binary drops or executes scripts at runtime, a common technique for executing commands, downloading additional payloads, or establishing persistence. Overlays containing scripts are highly indicative of malicious behavior.',
                        'script_types': found_scripts
                    })
                    risk_indicators.append('SCRIPT_IN_OVERLAY')
    else:
        findings.append({
            'category': 'No Overlay Data',
            'severity': 'INFO',
            'description': 'The binary does not contain overlay data. All bytes in the file are accounted for by the PE structure and declared sections. This is typical of most legitimate executables, though malware can also exist without overlays.'
        })
    
    # Calculate weighted risk score (max 15 points out of 100)
    risk_weights = {
        'PE_IN_OVERLAY': 12,
        'ENCRYPTED_OVERLAY': 10,
        'SCRIPT_IN_OVERLAY': 8,
        'OVERLAY_PRESENT': 3
    }
    risk_score = sum(risk_weights.get(indicator, 3) for indicator in risk_indicators)
    risk_score = min(risk_score, 15)  # Cap at 15
    
    pe.close()
    
    return {
        'overlay_present': overlay_size > 0,
        'overlay_size': overlay_size,
        'findings': findings,
        'risk_indicators': risk_indicators,
        'risk_score': risk_score
    }


def analyze_pe_structure(file_path):
    """
    Perform complete PE structure analysis using dumpbin and pefile
    
    Args:
        file_path (str): Path to PE file
        
    Returns:
        dict: Complete analysis results
    """
    dumpbin_exe = get_dumpbin_path()
    
    if not os.path.exists(dumpbin_exe):
        return {'error': f'dumpbin.exe not found at {dumpbin_exe}'}
    
    if not os.path.exists(file_path):
        return {'error': f'File not found: {file_path}'}
    
    print(f"Running dumpbin analysis on: {file_path}")
    
    # Run dumpbin commands
    imports_output = run_dumpbin(file_path, '/imports')
    exports_output = run_dumpbin(file_path, '/exports')
    headers_output = run_dumpbin(file_path, '/headers')
    
    # Parse outputs
    imports_data = parse_imports(imports_output) if imports_output else {'error': 'Failed to run dumpbin /imports'}
    exports_data = parse_exports(exports_output) if exports_output else {'error': 'Failed to run dumpbin /exports'}
    headers_data = parse_headers(headers_output) if headers_output else {'error': 'Failed to run dumpbin /headers'}
    
    # Analyze resources and timestamps using pefile
    print("Analyzing resources and timestamps with pefile...")
    resources_data = analyze_resources(file_path)
    timestamps_data = analyze_timestamps(file_path)
    
    # Analyze overlays for embedded payloads
    print("Analyzing overlays for embedded payloads...")
    overlays_data = analyze_overlays(file_path)
    
    # Calculate overall risk score
    total_risk = 0
    if 'analysis' in imports_data:
        total_risk += imports_data['analysis'].get('risk_score', 0)
    if 'analysis' in headers_data:
        total_risk += headers_data['analysis'].get('risk_score', 0)
    if 'risk_score' in resources_data:
        total_risk += resources_data.get('risk_score', 0)
    if 'risk_score' in timestamps_data:
        total_risk += timestamps_data.get('risk_score', 0)
    if 'risk_score' in overlays_data:
        total_risk += overlays_data.get('risk_score', 0)
    
    # Risk level thresholds (0-100 scale)
    # CRITICAL: 70-100 (extremely dangerous)
    # HIGH: 50-69 (very suspicious)
    # MEDIUM: 30-49 (moderately suspicious)
    # LOW: 0-29 (relatively safe)
    
    return {
        'imports': imports_data,
        'exports': exports_data,
        'sections': headers_data,
        'resources': resources_data,
        'timestamps': timestamps_data,
        'overlays': overlays_data,
        'overall_risk_score': min(total_risk, 100),  # Cap at 100
        'overall_risk_level': 'CRITICAL' if total_risk >= 70 else 'HIGH' if total_risk >= 50 else 'MEDIUM' if total_risk >= 30 else 'LOW'
    }
