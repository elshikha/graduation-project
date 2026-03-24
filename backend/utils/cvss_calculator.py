"""
CVSS (Common Vulnerability Scoring System) Calculator
Provides standardized risk scoring based on CVSS v3.1 methodology
Reference: https://www.first.org/cvss/v3.1/specification-document
"""


class CVSSCalculator:
    """
    Calculate CVSS-based risk scores for malware analysis
    
    CVSS Score Ranges:
    - None: 0.0
    - Low: 0.1 - 3.9
    - Medium: 4.0 - 6.9
    - High: 7.0 - 8.9
    - Critical: 9.0 - 10.0
    """
    
    # Risk factor weights
    WEIGHTS = {
        # Critical threats (3.0 points each)
        'code_execution': 3.0,          # Can execute arbitrary code
        'privilege_escalation': 3.0,    # Can escalate privileges
        'remote_exploit': 3.0,          # Remote code execution capability
        'system_modification': 2.5,     # Modifies system files/registry
        
        # High threats (2.0 points each)
        'data_exfiltration': 2.0,       # Can steal data
        'network_communication': 2.0,   # Network connections/C2
        'process_injection': 2.0,       # Code injection capabilities
        'anti_analysis': 2.0,           # Anti-debugging/VM detection
        'persistence': 2.0,             # Persistence mechanisms
        
        # Medium threats (1.0 points each)
        'packer_detected': 1.5,         # Packed/obfuscated
        'suspicious_imports': 1.0,      # Suspicious API imports
        'embedded_payload': 1.5,        # Embedded files/scripts
        'obfuscation': 1.0,             # Code obfuscation
        'encryption': 1.0,              # Encryption detected
        
        # Low threats (0.5 points each)
        'anomalous_structure': 0.5,     # Structural anomalies
        'suspicious_strings': 0.5,      # Suspicious string patterns
        'unsigned_binary': 0.3,         # Not digitally signed
        'high_entropy': 0.7,            # High entropy sections
    }
    
    @staticmethod
    def calculate_cvss_score(threat_indicators):
        """
        Calculate CVSS score based on detected threat indicators
        
        Args:
            threat_indicators (dict): Dictionary of threat indicators and their counts
                Example: {
                    'code_execution': 2,
                    'packer_detected': 1,
                    'suspicious_imports': 5
                }
        
        Returns:
            dict: {
                'cvss_score': float (0.0-10.0),
                'severity': str (None/Low/Medium/High/Critical),
                'threat_level': str (Safe/Suspicious/Dangerous/Malicious),
                'contributing_factors': list
            }
        """
        if not threat_indicators:
            return {
                'cvss_score': 0.0,
                'severity': 'None',
                'threat_level': 'Safe',
                'contributing_factors': []
            }
        
        total_score = 0.0
        contributing_factors = []
        
        # Calculate weighted score
        for indicator, count in threat_indicators.items():
            if indicator in CVSSCalculator.WEIGHTS:
                weight = CVSSCalculator.WEIGHTS[indicator]
                contribution = weight * min(count, 3)  # Cap at 3 occurrences
                total_score += contribution
                
                if contribution > 0:
                    contributing_factors.append({
                        'indicator': indicator,
                        'count': count,
                        'contribution': round(contribution, 2)
                    })
        
        # Normalize to CVSS 0-10 scale (cap at 10.0)
        cvss_score = min(total_score, 10.0)
        
        # Determine severity level
        severity = CVSSCalculator._get_severity(cvss_score)
        threat_level = CVSSCalculator._get_threat_level(cvss_score)
        
        # Sort contributing factors by impact
        contributing_factors.sort(key=lambda x: x['contribution'], reverse=True)
        
        return {
            'cvss_score': round(cvss_score, 1),
            'severity': severity,
            'threat_level': threat_level,
            'contributing_factors': contributing_factors[:10]  # Top 10 factors
        }
    
    @staticmethod
    def _get_severity(score):
        """Convert CVSS score to severity rating"""
        if score == 0.0:
            return 'None'
        elif score < 4.0:
            return 'Low'
        elif score < 7.0:
            return 'Medium'
        elif score < 9.0:
            return 'High'
        else:
            return 'Critical'
    
    @staticmethod
    def _get_threat_level(score):
        """Convert CVSS score to threat level description"""
        if score == 0.0:
            return 'Safe'
        elif score < 4.0:
            return 'Low Risk'
        elif score < 7.0:
            return 'Suspicious'
        elif score < 9.0:
            return 'Dangerous'
        else:
            return 'Malicious'
    
    @staticmethod
    def calculate_pdf_score(pdf_analysis):
        """
        Calculate CVSS score specifically for PDF analysis
        
        Args:
            pdf_analysis (dict): PDF analysis results
            
        Returns:
            dict: CVSS scoring results
        """
        threat_indicators = {}
        
        # Check structure analysis
        structure = pdf_analysis.get('structure', {})
        metadata = structure.get('metadata', {})
        suspicious_elements = structure.get('suspicious_elements', [])
        
        # JavaScript in PDF (code execution risk)
        if metadata.get('javascript_count', 0) > 0:
            threat_indicators['code_execution'] = metadata['javascript_count']
        
        # Launch actions (system modification)
        if metadata.get('launch_count', 0) > 0:
            threat_indicators['system_modification'] = metadata['launch_count']
        
        # Auto actions (code execution)
        if metadata.get('auto_action_count', 0) > 0:
            threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + metadata['auto_action_count']
        
        # OpenAction (code execution)
        if metadata.get('open_action_count', 0) > 0:
            threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + metadata['open_action_count']
        
        # Embedded files (embedded payload)
        if metadata.get('embedded_files', 0) > 0:
            threat_indicators['embedded_payload'] = metadata['embedded_files']
        
        # High entropy (packing/encryption)
        entropy = structure.get('entropy', {})
        total_entropy = entropy.get('total', 0)
        if total_entropy >= 7.5:
            threat_indicators['packer_detected'] = 1
            threat_indicators['encryption'] = 1
        elif total_entropy >= 7.0:
            threat_indicators['encryption'] = 1
        
        # Encryption
        peepdf_info = pdf_analysis.get('peepdf', {}).get('info', {})
        if peepdf_info.get('encrypted') == 'True':
            threat_indicators['encryption'] = 1
        
        # URIs (potential network communication)
        peepdf_suspicious = pdf_analysis.get('peepdf', {}).get('suspicious_elements', [])
        for item in peepdf_suspicious:
            if 'URIs' in str(item):
                threat_indicators['network_communication'] = 1
        
        # Parsing errors (anomalous structure)
        for item in peepdf_suspicious:
            if 'errors' in str(item).lower():
                threat_indicators['anomalous_structure'] = 1
        
        # YARA detections
        yara_results = pdf_analysis.get('yara', {})
        yara_matches = yara_results.get('matches', [])
        
        for match in yara_matches:
            rule_name = match.get('rule', '').lower()
            
            if 'exploit' in rule_name or 'malicious' in rule_name:
                threat_indicators['remote_exploit'] = threat_indicators.get('remote_exploit', 0) + 1
            elif 'obfuscation' in rule_name or 'obfuscated' in rule_name:
                threat_indicators['obfuscation'] = threat_indicators.get('obfuscation', 0) + 1
            elif 'suspicious' in rule_name:
                threat_indicators['suspicious_strings'] = threat_indicators.get('suspicious_strings', 0) + 1
        
        return CVSSCalculator.calculate_cvss_score(threat_indicators)
    
    @staticmethod
    def calculate_pe_score(pe_analysis):
        """
        Calculate CVSS score for PE (executable) analysis
        
        Args:
            pe_analysis (dict): PE analysis results
            
        Returns:
            dict: CVSS scoring results
        """
        threat_indicators = {}
        
        # CAPA analysis results
        capa_results = pe_analysis.get('capa', {})
        if capa_results.get('success'):
            capabilities = capa_results.get('capabilities', [])
            attack_tactics = capa_results.get('attack_tactics', [])
            
            # Analyze capabilities
            for cap in capabilities:
                cap_name = cap.get('capability', '').lower()
                namespace = cap.get('namespace', '').lower()
                
                # Code execution indicators
                if any(x in cap_name for x in ['execute', 'inject', 'shellcode', 'allocate executable']):
                    threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
                
                # Process injection
                if any(x in cap_name for x in ['inject', 'write process memory', 'create remote thread']):
                    threat_indicators['process_injection'] = threat_indicators.get('process_injection', 0) + 1
                
                # Privilege escalation
                if any(x in cap_name for x in ['escalate', 'privilege', 'token', 'impersonate']):
                    threat_indicators['privilege_escalation'] = threat_indicators.get('privilege_escalation', 0) + 1
                
                # Persistence
                if any(x in cap_name for x in ['persistence', 'startup', 'registry run', 'scheduled task']):
                    threat_indicators['persistence'] = threat_indicators.get('persistence', 0) + 1
                
                # Network communication
                if any(x in cap_name for x in ['socket', 'http', 'download', 'url', 'network', 'internet']):
                    threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
                
                # Data exfiltration
                if any(x in cap_name for x in ['exfiltrate', 'upload', 'send data', 'keylog', 'screenshot']):
                    threat_indicators['data_exfiltration'] = threat_indicators.get('data_exfiltration', 0) + 1
                
                # Anti-analysis
                if any(x in cap_name for x in ['anti', 'detect debugger', 'detect vm', 'sandbox']):
                    threat_indicators['anti_analysis'] = threat_indicators.get('anti_analysis', 0) + 1
                
                # System modification
                if any(x in cap_name for x in ['modify registry', 'delete file', 'create file', 'write file']):
                    threat_indicators['system_modification'] = threat_indicators.get('system_modification', 0) + 1
            
            # ATT&CK tactics indicate specific threat patterns
            if len(attack_tactics) >= 3:
                threat_indicators['remote_exploit'] = 1
        
        # DIE analysis - packer detection
        die_results = pe_analysis.get('die', {})
        if die_results.get('packer') or die_results.get('protector'):
            threat_indicators['packer_detected'] = 1
        
        # PE header analysis
        pe_info = pe_analysis.get('pe_header', {})
        sections = pe_info.get('sections', [])
        
        # High entropy sections
        high_entropy_sections = sum(1 for s in sections if s.get('entropy', 0) > 7.0)
        if high_entropy_sections > 0:
            threat_indicators['high_entropy'] = high_entropy_sections
        
        # Suspicious imports
        imports = pe_info.get('imports', [])
        suspicious_dlls = ['ws2_32.dll', 'wininet.dll', 'urlmon.dll']  # Network DLLs
        if any(dll.lower() in [imp.lower() for imp in imports] for dll in suspicious_dlls):
            threat_indicators['suspicious_imports'] = 1
        
        return CVSSCalculator.calculate_cvss_score(threat_indicators)
    
    @staticmethod
    def calculate_elf_score(elf_analysis):
        """
        Calculate CVSS score for ELF (Linux executable) analysis
        
        Args:
            elf_analysis (dict): ELF analysis results
            
        Returns:
            dict: CVSS scoring results
        """
        threat_indicators = {}
        
        # Packer detection
        packer_info = elf_analysis.get('packer', {})
        if packer_info.get('is_packed'):
            threat_indicators['packer_detected'] = 1
            threat_indicators['obfuscation'] = len(packer_info.get('indicators', []))
        
        # Hardening analysis - missing hardening increases risk
        hardening = elf_analysis.get('hardening', {})
        
        # No RELRO is a vulnerability indicator (not a threat, but reduces security)
        if hardening.get('relro', {}).get('level') == 'None':
            threat_indicators['anomalous_structure'] = threat_indicators.get('anomalous_structure', 0) + 1
        
        # No PIE (fixed address, easier to exploit)
        if not hardening.get('pie', {}).get('enabled', True):
            threat_indicators['anomalous_structure'] = threat_indicators.get('anomalous_structure', 0) + 1
        
        # NX disabled (executable stack - dangerous)
        if not hardening.get('nx', {}).get('enabled', True):
            threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
        
        # No stack canary
        if not hardening.get('stack_canary', {}).get('enabled', True):
            threat_indicators['anomalous_structure'] = threat_indicators.get('anomalous_structure', 0) + 1
        
        # Suspicious imports detection
        elf_info = elf_analysis.get('elf', {})
        suspicious_imports = elf_info.get('suspicious_imports', [])
        
        for imp in suspicious_imports:
            # High-risk imports
            if imp in ('ptrace', 'mprotect', 'clone', 'fork', 'execve', 'execvp'):
                threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
            elif imp in ('socket', 'connect', 'send', 'recv', 'sendto', 'recvfrom', 'bind', 'listen'):
                threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
            elif imp in ('dlopen', 'dlsym'):
                threat_indicators['process_injection'] = threat_indicators.get('process_injection', 0) + 1
            elif imp in ('chmod', 'chown', 'unlink', 'remove'):
                threat_indicators['system_modification'] = threat_indicators.get('system_modification', 0) + 1
            else:
                threat_indicators['suspicious_imports'] = threat_indicators.get('suspicious_imports', 0) + 1
        
        # RWX segments (code injection risk)
        segments = elf_info.get('segments', {})
        if segments.get('has_rwx'):
            threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
            threat_indicators['process_injection'] = threat_indicators.get('process_injection', 0) + 1
        
        # High entropy (encryption/packing)
        file_entropy = elf_info.get('file_entropy', 0)
        if file_entropy >= 7.5:
            threat_indicators['high_entropy'] = 1
            threat_indicators['encryption'] = 1
        elif file_entropy >= 7.0:
            threat_indicators['high_entropy'] = 1
        
        # High entropy sections
        sections = elf_info.get('sections', {})
        high_entropy_sections = sections.get('high_entropy_sections', [])
        if high_entropy_sections:
            threat_indicators['high_entropy'] = threat_indicators.get('high_entropy', 0) + len(high_entropy_sections)
        
        # Embedded payloads
        if elf_info.get('has_embedded_payloads'):
            threat_indicators['embedded_payload'] = len(elf_info.get('embedded_payloads', []))
        
        # URLs (network communication indicator)
        url_count = elf_info.get('url_count', 0)
        if url_count >= 5:
            threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
        
        # Raw syscalls (anti-analysis / evasion)
        syscalls = elf_info.get('syscalls', {})
        if syscalls.get('has_raw_syscalls'):
            threat_indicators['anti_analysis'] = threat_indicators.get('anti_analysis', 0) + 1
        
        # No symbols (stripped - obfuscation indicator)
        symbols = elf_info.get('symbols', {})
        if symbols.get('no_symbols'):
            threat_indicators['obfuscation'] = threat_indicators.get('obfuscation', 0) + 1
        
        # CAPA analysis results (if available for ELF)
        capa_results = elf_analysis.get('capa', {})
        if capa_results.get('success'):
            capabilities = capa_results.get('capabilities', [])
            attack_tactics = capa_results.get('attack_tactics', [])
            
            for cap in capabilities:
                cap_name = cap.get('capability', '').lower()
                
                # Code execution indicators
                if any(x in cap_name for x in ['execute', 'inject', 'shellcode']):
                    threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
                
                # Network communication
                if any(x in cap_name for x in ['socket', 'http', 'download', 'network']):
                    threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
                
                # Anti-analysis
                if any(x in cap_name for x in ['anti', 'debug', 'sandbox', 'vm detect']):
                    threat_indicators['anti_analysis'] = threat_indicators.get('anti_analysis', 0) + 1
            
            # ATT&CK tactics
            if len(attack_tactics) >= 3:
                threat_indicators['remote_exploit'] = 1
        
        return CVSSCalculator.calculate_cvss_score(threat_indicators)
    
    @staticmethod
    def calculate_office_score(office_analysis):
        """
        Calculate CVSS score for Office document analysis
        
        Args:
            office_analysis (dict): Office analysis results containing macro, url, and structure analysis
            
        Returns:
            dict: CVSS scoring results
        """
        threat_indicators = {}
        
        # Macro analysis results
        macro_analysis = office_analysis.get('macros', {})
        
        # VBA macros detected
        if macro_analysis.get('has_vba_macros'):
            threat_indicators['embedded_content'] = threat_indicators.get('embedded_content', 0) + 1
        
        # XLM macros (legacy, often malicious)
        if macro_analysis.get('has_xlm_macros'):
            threat_indicators['embedded_content'] = threat_indicators.get('embedded_content', 0) + 2
            threat_indicators['obfuscation'] = threat_indicators.get('obfuscation', 0) + 1
        
        # Auto-execution triggers
        auto_exec = macro_analysis.get('auto_exec_triggers', [])
        if auto_exec:
            threat_indicators['auto_execution'] = len(auto_exec)
            threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
        
        # Suspicious functions in macros
        suspicious_functions = macro_analysis.get('suspicious_functions', [])
        for func in suspicious_functions:
            func_name = func.get('function', '').lower() if isinstance(func, dict) else str(func).lower()
            
            if 'shell' in func_name or 'powershell' in func_name:
                threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
            elif 'download' in func_name or 'http' in func_name or 'url' in func_name:
                threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
            elif 'exec' in func_name or 'run' in func_name:
                threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
            elif 'registry' in func_name or 'reg' in func_name:
                threat_indicators['system_modification'] = threat_indicators.get('system_modification', 0) + 1
            else:
                threat_indicators['suspicious_strings'] = threat_indicators.get('suspicious_strings', 0) + 1
        
        # Obfuscation patterns
        obfuscation = macro_analysis.get('obfuscation_patterns', [])
        if obfuscation:
            threat_indicators['obfuscation'] = threat_indicators.get('obfuscation', 0) + len(obfuscation)
        
        # IOCs detected
        iocs = macro_analysis.get('iocs', [])
        if iocs:
            threat_indicators['suspicious_strings'] = threat_indicators.get('suspicious_strings', 0) + len(iocs)
        
        # URL analysis results
        url_analysis = office_analysis.get('urls', {})
        
        # Suspicious URLs
        suspicious_urls = url_analysis.get('suspicious_urls', 0)
        if suspicious_urls > 0:
            threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
            threat_indicators['suspicious_strings'] = threat_indicators.get('suspicious_strings', 0) + suspicious_urls
        
        # External templates (template injection attack)
        templates = url_analysis.get('templates', [])
        if templates:
            threat_indicators['remote_exploit'] = threat_indicators.get('remote_exploit', 0) + 1
            threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
        
        # OLE objects
        ole_objects = url_analysis.get('ole_objects', [])
        if ole_objects:
            threat_indicators['embedded_content'] = threat_indicators.get('embedded_content', 0) + len(ole_objects)
        
        # UNC paths (SMB attacks)
        unc_paths = url_analysis.get('unc_paths', [])
        if unc_paths:
            threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
            threat_indicators['data_exfiltration'] = threat_indicators.get('data_exfiltration', 0) + 1
        
        # URL threat scores
        urls = url_analysis.get('urls', [])
        for url_info in urls:
            if isinstance(url_info, dict):
                threats = url_info.get('threats', [])
                if 'Executable Extension' in threats:
                    threat_indicators['code_execution'] = threat_indicators.get('code_execution', 0) + 1
                if 'Direct IP Address' in threats or 'UNC Path' in threats:
                    threat_indicators['network_communication'] = threat_indicators.get('network_communication', 0) + 1
        
        # Structure analysis results
        structure = office_analysis.get('structure', {})
        
        # High entropy (encryption/compression)
        overall_entropy = structure.get('overall_entropy', 0)
        if overall_entropy >= 7.5:
            threat_indicators['high_entropy'] = 1
            threat_indicators['encryption'] = 1
        elif overall_entropy >= 7.0:
            threat_indicators['high_entropy'] = 1
        
        # Encrypted document
        if structure.get('is_encrypted'):
            threat_indicators['encryption'] = threat_indicators.get('encryption', 0) + 1
        
        # Suspicious OLE streams
        ole_streams = structure.get('ole_streams', [])
        for stream in ole_streams:
            if isinstance(stream, dict):
                stream_name = stream.get('name', '').lower()
                if 'macro' in stream_name or 'vba' in stream_name:
                    threat_indicators['embedded_content'] = threat_indicators.get('embedded_content', 0) + 1
                elif 'object' in stream_name or 'ole' in stream_name:
                    threat_indicators['embedded_content'] = threat_indicators.get('embedded_content', 0) + 1
        
        return CVSSCalculator.calculate_cvss_score(threat_indicators)
    
    @staticmethod
    def get_recommendation(cvss_result):
        """
        Get security recommendation based on CVSS score
        
        Args:
            cvss_result (dict): CVSS calculation result
            
        Returns:
            str: Security recommendation
        """
        severity = cvss_result['severity']
        
        recommendations = {
            'None': 'File appears safe. No malicious indicators detected.',
            'Low': 'File shows minor suspicious characteristics. Proceed with caution and verify source.',
            'Medium': 'File exhibits suspicious behavior. Recommend sandboxed analysis before execution.',
            'High': 'File demonstrates dangerous capabilities. Do NOT execute without proper containment.',
            'Critical': 'File is highly likely malicious. QUARANTINE immediately and perform full forensic analysis.'
        }
        
        return recommendations.get(severity, 'Unable to determine safety level.')
