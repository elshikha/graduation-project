"""
DIE (Detect It Easy) Analyzer
Provides file analysis using DIE tool for compiler detection, packer detection, and file signatures
"""

import subprocess
import os
import json


def run_die_analysis(file_path):
    """
    Run DIE (Detect It Easy) analysis on a file with JSON output
    
    Args:
        file_path (str): Path to the file to analyze
        
    Returns:
        dict: Parsed DIE analysis results
    """
    # Path to diec.exe in the External folder
    die_exe = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        'External', 'die', 'diec.exe'
    )
    
    if not os.path.exists(die_exe):
        return {
            'error': 'DIE tool not found',
            'path_checked': die_exe
        }
    
    if not os.path.exists(file_path):
        return {'error': 'File not found'}
    
    # Convert to absolute path to avoid path issues
    abs_file_path = os.path.abspath(file_path)
    
    try:
        # Run diec.exe with heuristic scan, verbose, deep scan, and JSON output
        result = subprocess.run(
            [die_exe, abs_file_path, '--heuristicscan', '--verbose', '--deepscan', '-j'],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.dirname(die_exe)
        )
        
        output = result.stdout
        stderr = result.stderr
        
        if not output:
            return {'error': 'No output from DIE tool', 'stderr': stderr}
        
        # Log the raw output for debugging
        print(f"\n=== DIE RAW OUTPUT ===")
        print(output)
        print(f"=== DIE STDERR ===")
        print(stderr)
        print(f"=== END DIE OUTPUT ===\n")
        
        # Try JSON parsing first
        parsed_result = parse_die_json_output(output)
        
        # If JSON parsing failed, try text parsing as fallback
        if 'error' in parsed_result:
            print("JSON parsing failed, trying text format...")
            parsed_result = parse_die_text_output(output)
        
        # If both failed, include raw output for debugging
        if 'error' in parsed_result and 'raw_output' not in parsed_result:
            parsed_result['raw_output'] = output[:1000]  # Limit to first 1000 chars
            
        return parsed_result
        
    except subprocess.TimeoutExpired:
        return {'error': 'DIE analysis timed out'}
    except Exception as e:
        return {'error': f'Failed to run DIE analysis: {str(e)}'}


def parse_die_json_output(output):
    """
    Parse DIE tool JSON output into structured data
    
    Args:
        output (str): Raw JSON output from diec.exe
        
    Returns:
        dict: Structured DIE analysis results
    """
    result = {
        'file_type': None,
        'operation_system': None,
        'compiler': None,
        'language': None,
        'sign_tool': None,
        'packer': None,
        'protector': None,
        'overlay': None,
        'linker': None,
        'library': None,
        'tool': None,
        'detections': [],
        'heuristic_messages': [],
        'all_detections': []
    }
    
    try:
        # Extract JSON portion from output (may have heuristic messages before JSON)
        lines = output.strip().split('\n')
        json_lines = []
        in_json = False
        brace_count = 0
        
        # Find and extract JSON content
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            # Collect heuristic messages (lines starting with [HEUR)
            if stripped.startswith('[HEUR'):
                result['heuristic_messages'].append(line)
                continue
            
            # Check if this line starts JSON
            if not in_json and stripped.startswith('{'):
                in_json = True
                json_lines.append(line)
                brace_count += line.count('{') - line.count('}')
            elif in_json:
                json_lines.append(line)
                brace_count += line.count('{') - line.count('}')
                
                # Check if JSON is complete
                if brace_count == 0:
                    break
        
        if not json_lines:
            # Try to find JSON in a single line
            for line in lines:
                if '{' in line and 'detects' in line:
                    # Extract JSON from line (might have text before/after)
                    start_idx = line.find('{')
                    if start_idx != -1:
                        json_lines = [line[start_idx:]]
                        break
        
        if not json_lines:
            return {
                'error': 'Could not find JSON in DIE output', 
                'raw_output': output,
                'note': 'DIE tool may need different parameters or JSON output is not available'
            }
        
        # Parse JSON
        json_text = '\n'.join(json_lines)
        data = json.loads(json_text)
        
        # Process detects array
        if 'detects' in data and len(data['detects']) > 0:
            for detect in data['detects']:
                # Store file type
                if 'filetype' in detect:
                    result['file_type'] = detect['filetype']
                
                # Process values array
                if 'values' in detect:
                    for value_item in detect['values']:
                        detection_info = {
                            'type': value_item.get('type', ''),
                            'name': value_item.get('name', ''),
                            'version': value_item.get('version', ''),
                            'info': value_item.get('info', ''),
                            'string': value_item.get('string', '')
                        }
                        
                        result['all_detections'].append(detection_info)
                        
                        # Map to specific fields
                        det_type = value_item.get('type', '').lower()
                        det_string = value_item.get('string', '')
                        
                        if 'operation system' in det_type or 'operating system' in det_type:
                            result['operation_system'] = det_string
                        elif 'compiler' in det_type:
                            result['compiler'] = det_string
                        elif 'language' in det_type:
                            result['language'] = det_string
                        elif 'sign tool' in det_type:
                            result['sign_tool'] = det_string
                        elif 'packer' in det_type:
                            result['packer'] = det_string
                        elif 'protector' in det_type:
                            result['protector'] = det_string
                        elif 'overlay' in det_type:
                            result['overlay'] = det_string
                        elif 'linker' in det_type:
                            result['linker'] = det_string
                        elif 'library' in det_type:
                            result['library'] = det_string
                        elif 'tool' in det_type and 'sign' not in det_type:
                            result['tool'] = det_string
        
        # Remove None values and empty lists
        result = {k: v for k, v in result.items() if v is not None and v != []}
        
        return result
        
    except json.JSONDecodeError as e:
        return {'error': f'Failed to parse JSON output: {str(e)}', 'raw_output': output}
    except Exception as e:
        return {'error': f'Failed to process DIE output: {str(e)}', 'raw_output': output}


def get_die_summary(die_result):
    """
    Get a summary of the most important DIE findings
    
    Args:
        die_result (dict): Parsed DIE results
        
    Returns:
        dict: Summary of key findings
    """
    if 'error' in die_result:
        return die_result
    
    summary = {}
    
    # Key fields to include in summary
    important_fields = [
        'file_type',
        'operation_system',
        'compiler',
        'language',
        'packer',
        'protector',
        'sign_tool'
    ]
    
    for field in important_fields:
        if field in die_result:
            summary[field] = die_result[field]
    
    return summary


def parse_die_text_output(output):
    """
    Parse DIE tool text output (fallback when JSON is not available)
    
    Args:
        output (str): Raw text output from diec.exe
        
    Returns:
        dict: Structured DIE analysis results
    """
    result = {
        'file_type': None,
        'operation_system': None,
        'compiler': None,
        'language': None,
        'sign_tool': None,
        'packer': None,
        'protector': None,
        'all_detections': [],
        'heuristic_messages': []
    }
    
    lines = output.strip().split('\n')
    in_detection_section = False
    
    for line in lines:
        stripped = line.strip()
        
        # Skip empty lines
        if not stripped:
            continue
        
        # Collect heuristic messages
        if stripped.startswith('[HEUR'):
            result['heuristic_messages'].append(stripped)
            continue
        
        # First non-heuristic line is usually file type
        if not in_detection_section and not stripped.startswith('[') and not result['file_type']:
            result['file_type'] = stripped
            in_detection_section = True
            continue
        
        # Parse detection lines (indented with 4 spaces and contain ':')
        if in_detection_section and line.startswith('    ') and ':' in stripped:
            # Remove (Heur) prefix
            line_clean = stripped.replace('(Heur)', '').strip()
            
            # Extract type and value
            parts = line_clean.split(':', 1)
            if len(parts) == 2:
                det_type = parts[0].strip()
                det_value = parts[1].strip()
                
                # Store detection
                result['all_detections'].append({
                    'type': det_type,
                    'string': line_clean
                })
                
                # Map to specific fields
                type_lower = det_type.lower()
                if 'operation system' in type_lower or 'operating system' in type_lower:
                    result['operation_system'] = line_clean
                elif 'compiler' in type_lower:
                    result['compiler'] = line_clean
                elif 'language' in type_lower:
                    result['language'] = line_clean
                elif 'sign tool' in type_lower:
                    result['sign_tool'] = line_clean
                elif 'packer' in type_lower:
                    result['packer'] = line_clean
                elif 'protector' in type_lower:
                    result['protector'] = line_clean
    
    # Remove empty fields
    result = {k: v for k, v in result.items() if v is not None and v != []}
    
    # If no detections found, return error
    if not result.get('all_detections') and not result.get('file_type'):
        return {'error': 'Could not parse DIE text output', 'raw_output': output[:500]}
    
    return result


def format_die_detections(die_result):
    """
    Format all DIE detections for display
    
    Args:
        die_result (dict): Parsed DIE results
        
    Returns:
        list: List of formatted detection strings
    """
    if 'error' in die_result:
        return []
    
    detections = []
    
    if 'all_detections' in die_result:
        for detection in die_result['all_detections']:
            # Use the formatted string if available
            if detection.get('string'):
                detections.append(detection['string'])
            else:
                # Build a string from components
                parts = []
                if detection.get('type'):
                    parts.append(detection['type'])
                if detection.get('name'):
                    parts.append(detection['name'])
                if detection.get('version'):
                    parts.append(f"({detection['version']})")
                if detection.get('info'):
                    parts.append(f"[{detection['info']}]")
                
                if parts:
                    detections.append(': '.join(parts[:2]) + ' ' + ' '.join(parts[2:]))
    
    return detections

    
    # Add warning flags
    warnings = []
    if die_result.get('packer'):
        warnings.append('File appears to be packed/compressed')
    if die_result.get('protector'):
        warnings.append('File has protector/obfuscation detected')
    if not die_result.get('sign_tool'):
        warnings.append('No digital signature detected')
    
    if warnings:
        summary['warnings'] = warnings
    
    return summary
