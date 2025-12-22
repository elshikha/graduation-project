"""
CAPA Capability Analyzer
Analyzes PE files using CAPA to extract capabilities, ATT&CK techniques, and MBC behaviors
"""

import subprocess
import re
import os
import json
from pathlib import Path


class CapaAnalyzer:
    def __init__(self):
        # Path to capa.exe and rules
        self.base_dir = Path(__file__).parent.parent.parent
        self.capa_exe = self.base_dir / "external" / "capa" / "capa.exe"
        self.capa_rules = self.base_dir / "external" / "capa" / "capa-rules"
        
        if not self.capa_exe.exists():
            raise FileNotFoundError(f"CAPA executable not found at {self.capa_exe}")
        if not self.capa_rules.exists():
            raise FileNotFoundError(f"CAPA rules not found at {self.capa_rules}")
    
    def analyze(self, pe_path):
        """
        Run CAPA analysis on a PE file
        
        Args:
            pe_path: Path to PE file to analyze
            
        Returns:
            dict: Analysis results containing file info, ATT&CK, MBC, and capabilities
        """
        try:
            # Build command - use JSON output for reliable parsing
            cmd = [
                str(self.capa_exe),
                str(pe_path),
                "-r", str(self.capa_rules),
                "-j"  # JSON output for easier parsing
            ]
            
            print(f"[CAPA] Running: {' '.join(cmd)}")
            
            # Run CAPA
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=720  # 12 minute timeout
            )
            
            if result.returncode != 0:
                print(f"[CAPA] Warning: Non-zero exit code {result.returncode}")
                print(f"[CAPA] STDERR: {result.stderr}")
            
            output = result.stdout
            
            if not output:
                return {
                    "success": False,
                    "error": "No output from CAPA",
                    "stderr": result.stderr
                }
            
            # Parse JSON output
            try:
                json_data = json.loads(output)
                parsed_data = self._parse_capa_json(json_data)
                parsed_data["success"] = True
                return parsed_data
            except json.JSONDecodeError as je:
                print(f"[CAPA] JSON parse error: {je}")
                # Fallback to text parsing
                parsed_data = self._parse_capa_output(output)
                parsed_data["raw_output"] = output
                parsed_data["success"] = True
                return parsed_data
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "CAPA analysis timed out after 12 minutes"
            }
        except Exception as e:
            print(f"[CAPA] Exception: {e}")
            import traceback
            traceback.print_exc()
            return {
                "success": False,
                "error": f"CAPA analysis failed: {str(e)}"
            }
    
    def _parse_capa_output(self, output):
        """Parse CAPA text output into structured data"""
        
        data = {
            "file_info": {},
            "attack_tactics": [],
            "mbc_objectives": [],
            "capabilities": []
        }
        
        lines = output.split('\n')
        
        # State machine for parsing sections
        current_section = None
        
        for i, line in enumerate(lines):
            # Parse file info table (md5, sha256, os, format, arch, etc.)
            if '│ md5' in line or '│ sha1' in line or '│ sha256' in line:
                parts = line.split('│')
                if len(parts) >= 3:
                    key = parts[1].strip()
                    value = parts[2].strip()
                    data["file_info"][key] = value
            
            elif '│ analysis' in line or '│ os' in line or '│ format' in line or '│ arch' in line:
                parts = line.split('│')
                if len(parts) >= 3:
                    key = parts[1].strip()
                    value = parts[2].strip()
                    data["file_info"][key] = value
            
            # Detect ATT&CK section
            elif 'ATT&CK Tactic' in line and 'ATT&CK Technique' in line:
                current_section = 'attack'
                continue
            
            # Detect MBC section
            elif 'MBC Objective' in line and 'MBC Behavior' in line:
                current_section = 'mbc'
                continue
            
            # Detect Capability section
            elif 'Capability' in line and 'Namespace' in line:
                current_section = 'capability'
                continue
            
            # Parse based on current section
            if current_section == 'attack':
                # Look for lines with actual data (not separators)
                if '│' in line and '┃' not in line and '┡' not in line and '└' not in line:
                    parts = line.split('│')
                    if len(parts) >= 3:
                        tactic = parts[1].strip()
                        technique = parts[2].strip()
                        
                        if tactic and technique and tactic != 'ATT&CK Tactic':
                            # Extract technique ID from brackets
                            technique_match = re.search(r'\[([T]\d+(?:\.\d+)?)\]', technique)
                            technique_id = technique_match.group(1) if technique_match else ""
                            technique_name = re.sub(r'\[.*?\]', '', technique).strip()
                            
                            data["attack_tactics"].append({
                                "tactic": tactic,
                                "technique": technique_name,
                                "technique_id": technique_id
                            })
            
            elif current_section == 'mbc':
                if '│' in line and '┃' not in line and '┡' not in line and '└' not in line:
                    parts = line.split('│')
                    if len(parts) >= 3:
                        objective = parts[1].strip()
                        behavior = parts[2].strip()
                        
                        if objective and behavior and objective != 'MBC Objective':
                            # Extract MBC ID from brackets
                            mbc_match = re.search(r'\[([BCEF]\d+(?:\.\d+)?(?:\.m?\d+)?)\]', behavior)
                            mbc_id = mbc_match.group(1) if mbc_match else ""
                            behavior_name = re.sub(r'\[.*?\]', '', behavior).strip()
                            
                            data["mbc_objectives"].append({
                                "objective": objective,
                                "behavior": behavior_name,
                                "mbc_id": mbc_id
                            })
            
            elif current_section == 'capability':
                if '│' in line and '┃' not in line and '┡' not in line and '└' not in line:
                    parts = line.split('│')
                    if len(parts) >= 3:
                        capability = parts[1].strip()
                        namespace = parts[2].strip()
                        
                        if capability and namespace and capability != 'Capability':
                            # Extract match count
                            match_count = 1
                            match_pattern = re.search(r'\((\d+)\s+matches?\)', capability)
                            if match_pattern:
                                match_count = int(match_pattern.group(1))
                                capability = re.sub(r'\(\d+\s+matches?\)', '', capability).strip()
                            
                            data["capabilities"].append({
                                "capability": capability,
                                "namespace": namespace,
                                "match_count": match_count
                            })
        
        return data
    
    def _parse_capa_json(self, json_data):
        """Parse CAPA JSON output into structured data"""
        
        data = {
            "file_info": {},
            "attack_tactics": [],
            "mbc_objectives": [],
            "capabilities": []
        }
        
        # Extract metadata/file info
        if "meta" in json_data:
            meta = json_data["meta"]
            if "sample" in meta:
                sample = meta["sample"]
                data["file_info"] = {
                    "md5": sample.get("md5", ""),
                    "sha1": sample.get("sha1", ""),
                    "sha256": sample.get("sha256", ""),
                    "analysis": meta.get("analysis", {}).get("format", ""),
                    "os": meta.get("analysis", {}).get("os", ""),
                    "format": meta.get("analysis", {}).get("format", ""),
                    "arch": meta.get("analysis", {}).get("arch", "")
                }
        
        # Extract rules/capabilities
        if "rules" in json_data:
            rules = json_data["rules"]
            print(f"[CAPA] Found {len(rules)} rules in JSON")
            
            # Track unique ATT&CK and MBC entries
            attack_set = set()
            mbc_set = set()
            
            for rule_name, rule_data in rules.items():
                if not isinstance(rule_data, dict):
                    continue
                
                meta = rule_data.get("meta", {})
                namespace = meta.get("namespace", "uncategorized")
                
                # Extract ATT&CK techniques (JSON uses 'attack' not 'att&ck')
                attack_list = meta.get("attack", [])
                if attack_list:
                    for attack in attack_list:
                        if isinstance(attack, dict):
                            tactic = attack.get("tactic", "")
                            technique = attack.get("technique", "")
                            technique_id = attack.get("id", "")
                            
                            if tactic and technique:
                                attack_key = f"{tactic}::{technique}::{technique_id}"
                                if attack_key not in attack_set:
                                    attack_set.add(attack_key)
                                    data["attack_tactics"].append({
                                        "tactic": tactic.upper(),
                                        "technique": technique,
                                        "technique_id": technique_id
                                    })
                
                # Extract MBC objectives
                if "mbc" in meta:
                    for mbc in meta["mbc"]:
                        if isinstance(mbc, dict):
                            objective = mbc.get("objective", [""])[0] if isinstance(mbc.get("objective"), list) else mbc.get("objective", "")
                            behavior = mbc.get("behavior", [""])[0] if isinstance(mbc.get("behavior"), list) else mbc.get("behavior", "")
                            mbc_id = mbc.get("id", "")
                        else:
                            # String format: "Objective::Behavior [B1234]"
                            parts = mbc.split("::")
                            objective = parts[0].strip() if len(parts) > 0 else ""
                            behavior_part = parts[-1].strip() if len(parts) > 1 else ""
                            
                            # Extract ID
                            id_match = re.search(r'\[([BCEF]\d+(?:\.\d+)?(?:\.m?\d+)?)\]', behavior_part)
                            mbc_id = id_match.group(1) if id_match else ""
                            behavior = re.sub(r'\[.*?\]', '', behavior_part).strip()
                        
                        if objective and behavior:
                            mbc_key = f"{objective}::{behavior}::{mbc_id}"
                            if mbc_key not in mbc_set:
                                mbc_set.add(mbc_key)
                                data["mbc_objectives"].append({
                                    "objective": objective.upper(),
                                    "behavior": behavior,
                                    "mbc_id": mbc_id
                                })
                
                # Add capability
                capability_name = meta.get("name", rule_name)
                match_count = len(rule_data.get("matches", {}))
                
                data["capabilities"].append({
                    "capability": capability_name,
                    "namespace": namespace,
                    "match_count": max(1, match_count)
                })
        
        print(f"[CAPA] Parsed: {len(data['attack_tactics'])} ATT&CK, {len(data['mbc_objectives'])} MBC, {len(data['capabilities'])} capabilities")
        
        return data
    
    def get_rule_content(self, namespace, capability_name):
        """
        Find and read YAML rule file for a given capability
        
        Args:
            namespace: Rule namespace (e.g., 'anti-analysis/anti-debugging')
            capability_name: Name of the capability
            
        Returns:
            dict: Rule content or error
        """
        try:
            # Convert namespace to path
            namespace_path = namespace.replace('/', os.sep)
            
            # Search for matching YAML files in the namespace directory
            rule_dir = self.capa_rules / namespace_path
            
            if not rule_dir.exists():
                return {
                    "success": False,
                    "error": f"Namespace directory not found: {namespace}"
                }
            
            # Search for YAML files matching the capability
            yaml_files = list(rule_dir.glob("*.yml"))
            
            # Try to find matching rule file
            matching_file = None
            for yaml_file in yaml_files:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Check if the file contains a matching rule name
                    if f'name: {capability_name}' in content:
                        matching_file = yaml_file
                        break
            
            if matching_file:
                with open(matching_file, 'r', encoding='utf-8') as f:
                    rule_content = f.read()
                
                return {
                    "success": True,
                    "rule_content": rule_content,
                    "file_path": str(matching_file.relative_to(self.capa_rules)),
                    "capability": capability_name,
                    "namespace": namespace
                }
            else:
                # Return list of available rules in namespace
                available_rules = [f.name for f in yaml_files]
                return {
                    "success": False,
                    "error": f"Rule not found for capability: {capability_name}",
                    "available_rules": available_rules,
                    "searched_in": str(rule_dir.relative_to(self.capa_rules))
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to read rule: {str(e)}"
            }


# Test function
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python capa_analyzer.py <pe_file_path>")
        sys.exit(1)
    
    analyzer = CapaAnalyzer()
    results = analyzer.analyze(sys.argv[1])
    
    print(json.dumps(results, indent=2))
