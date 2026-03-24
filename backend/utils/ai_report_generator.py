"""
AI Report Generator and Behavioral Graph Builder

This module integrates LLM-based report generation and relational graph building
into the malware analysis platform.
"""

import json
import requests
import logging
from pathlib import Path
from datetime import datetime

# Configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:3b"

logger = logging.getLogger(__name__)


# ===== PROMPTS =====

ENGLISH_ANALYSIS_PROMPT = """You are a world-class malware reverse engineer and threat intelligence analyst with 15+ years of experience in a Tier-1 Security Operations Center (SOC). You have deep expertise in PE, ELF, PDF, and Office malware analysis.

You will receive structured malware analysis data in JSON format from automated analysis systems.

Your mission: Transform this raw data into a **comprehensive, actionable, and professional** malware intelligence report that would satisfy the most demanding security leadership.

## YOUR ANALYSIS APPROACH:

1. **Think like an attacker**: What is the malware trying to accomplish? What attack chain does it fit into?
2. **Connect the dots**: How do individual indicators combine to reveal the full threat picture?
3. **Provide actionable intelligence**: Every finding should lead to a clear defensive action.
4. **Be specific**: Reference exact values from the data (hashes, API names, scores, etc.)

## CRITICAL RULES:
- Base ALL conclusions on the provided JSON data - cite specific evidence
- Use precise technical terminology (CVE IDs, MITRE ATT&CK IDs, etc.)
- Quantify risk with specific metrics from the analysis
- If data is limited, explicitly state what additional analysis would help
- Write for a technical audience but ensure executives can understand key findings

## REQUIRED OUTPUT FORMAT:

# 🔒 Malware Intelligence Report

**File**: [filename]
**Type**: [file type]
**Analysis Date**: [current date]
**Classification**: [MALICIOUS/SUSPICIOUS/BENIGN]
**Risk Score**: [X/10]

---

## 📋 Executive Summary

Provide a 3-4 sentence high-impact summary that answers:
- **What is this file?** (e.g., "This is a PyInstaller-packed Linux executable exhibiting characteristics consistent with...")
- **What is the threat level and why?** (Reference specific CVSS score, detection ratio, or capability findings)
- **What immediate action is required?** (Quarantine, investigate, monitor, etc.)

---

## 🔬 Technical Analysis

### File Properties
- Document key file attributes (size, entropy, architecture, compilation info)
- Highlight anomalies (unusually high entropy, stripped symbols, suspicious sections)

### Detected Capabilities
For each capability category found, explain:
- **What it does**: Technical description
- **Why it matters**: Security implications
- **Evidence**: Cite specific APIs, functions, or patterns from the data

Organize by threat category:
- **Execution & Process Manipulation**
- **Persistence Mechanisms**  
- **Defense Evasion & Anti-Analysis**
- **Discovery & Reconnaissance**
- **Collection & Exfiltration**
- **Command & Control**

### Packer/Obfuscation Analysis
- Identify any packers, crypters, or obfuscation
- Explain implications for analysis and detection

### Security Posture (for ELF/PE)
- Document security features present/missing (PIE, RELRO, Stack Canary, NX, ASLR)
- Explain what missing protections enable

---

## ⚠️ Indicators of Compromise (IOCs)

Extract and list all IOCs found:

| Type | Value | Context |
|------|-------|----------|
| SHA256 | [hash] | File hash |
| IP | [ip] | Network indicator |
| URL | [url] | C2 or download |
| Registry | [key] | Persistence |
| File Path | [path] | Dropped files |

---

## 🎯 MITRE ATT&CK Mapping

Map observed behaviors to specific techniques:

| Technique ID | Name | Tactic | Evidence |
|--------------|------|--------|----------|
| T1059.004 | Unix Shell | Execution | [specific evidence] |
| T1027 | Obfuscated Files | Defense Evasion | [specific evidence] |

*(Include 3-8 most relevant techniques based on actual evidence)*

---

## 📊 Risk Assessment

**Overall Risk Level**: [Critical/High/Medium/Low]

**Risk Score Breakdown**:
- Capability Score: X/10 (based on detected malicious capabilities)
- Evasion Score: X/10 (based on anti-analysis techniques)
- Impact Potential: X/10 (based on what the malware could do)

**Justification**: Explain why this risk level was assigned using 3-5 specific evidence points.

---

## 🛡️ Recommended Actions

### Immediate (Within 24 hours)
1. [Specific containment action]
2. [Specific investigation step]

### Short-term (Within 1 week)
1. [Detection rule to implement]
2. [Monitoring to enable]

### Long-term (Ongoing)
1. [Security control improvement]
2. [Process or policy update]

---

## 📝 Analyst Notes

**Confidence Level**: [High/Medium/Low]

**Analysis Limitations**:
- List what data was missing or incomplete
- Suggest additional analysis (dynamic analysis, sandbox, etc.)

**Related Threat Intelligence**:
- Mention any known malware families this resembles
- Reference similar TTPs from known threat actors if applicable

---

*Report generated by AI-assisted analysis. Manual verification recommended for critical findings.*

The structured JSON input will follow.
"""


# Prompt for generating clean graph node labels
GRAPH_LABELS_PROMPT = """You are a malware analyst creating a visualization graph. Convert the raw analysis data into clean, human-readable node labels.

For each node in the input, generate a SHORT, CLEAR label (max 25 characters) and a one-line description.

Rules:
- Labels must be concise and meaningful (e.g., "Process Injection" not "{'contribution': 1.5, 'indicators': [...]}")
- Use plain English, no JSON or code syntax
- Focus on WHAT the capability/indicator does
- Risk indicators should describe the threat behavior

Return ONLY valid JSON in this exact format:
{
  "nodes": [
    {"id": "original_id", "label": "Clean Label", "description": "One line explanation"}
  ]
}

INPUT DATA:"""


def _generate_llm_graph_labels(nodes_for_llm: list) -> dict:
    """
    Use LLM to generate clean, meaningful labels for graph nodes.
    
    Args:
        nodes_for_llm: List of nodes with raw labels needing improvement
    
    Returns:
        dict mapping node_id to improved label/description
    """
    if not nodes_for_llm:
        return {}
    
    try:
        prompt = f"""{GRAPH_LABELS_PROMPT}
{json.dumps(nodes_for_llm, indent=2)}

Return ONLY the JSON response, no other text."""

        payload = {
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_predict": 2048
            }
        }
        
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)
        
        if response.status_code == 200:
            response_text = response.json().get("response", "")
            # Try to extract JSON from response
            try:
                # Find JSON in response
                start = response_text.find('{')
                end = response_text.rfind('}') + 1
                if start >= 0 and end > start:
                    json_str = response_text[start:end]
                    result = json.loads(json_str)
                    # Build lookup dict
                    labels_map = {}
                    for node in result.get("nodes", []):
                        labels_map[node["id"]] = {
                            "label": node.get("label", ""),
                            "description": node.get("description", "")
                        }
                    return labels_map
            except json.JSONDecodeError:
                logger.warning("Failed to parse LLM graph labels response")
                return {}
        
        return {}
    except Exception as e:
        logger.error(f"Error generating LLM graph labels: {e}")
        return {}


def _clean_factor_label(factor) -> tuple:
    """
    Convert a contributing factor to a clean label without relying on LLM.
    Returns (label, description, risk_level)
    """
    # Mapping of indicator codes to human-readable names (from cvss_calculator WEIGHTS)
    indicator_names = {
        # Critical threats
        "code_execution": "Code Execution",
        "privilege_escalation": "Privilege Escalation",
        "remote_exploit": "Remote Exploit",
        "system_modification": "System Modification",
        
        # High threats
        "data_exfiltration": "Data Exfiltration",
        "network_communication": "Network Activity",
        "process_injection": "Process Injection",
        "anti_analysis": "Anti-Analysis",
        "persistence": "Persistence",
        
        # Medium threats
        "packer_detected": "Packer Detected",
        "suspicious_imports": "Suspicious Imports",
        "embedded_payload": "Embedded Payload",
        "obfuscation": "Obfuscation",
        "encryption": "Encryption Used",
        
        # Low threats
        "anomalous_structure": "Anomalous Structure",
        "suspicious_strings": "Suspicious Strings",
        "unsigned_binary": "Unsigned Binary",
        "high_entropy": "High Entropy",
        
        # Additional common indicators
        "keylogger": "Keylogger Activity",
        "crypto_operations": "Crypto Operations",
        "registry_access": "Registry Access",
        "anti_debug": "Anti-Debug",
        "anti_vm": "Anti-VM/Sandbox",
        "shellcode": "Shellcode Detected",
        "ransomware": "Ransomware Behavior",
        "trojan": "Trojan Behavior",
        "backdoor": "Backdoor Behavior",
        "rootkit": "Rootkit Behavior",
        "downloader": "Downloader Activity",
        "dropper": "Dropper Behavior",
        "c2_communication": "C2 Communication",
        "credential_theft": "Credential Theft",
        "discovery": "System Discovery",
        "lateral_movement": "Lateral Movement",
        "defense_evasion": "Defense Evasion",
        "auto_execute": "Auto-Execute",
        "malicious_macro": "Malicious Macro",
        "embedded_executable": "Embedded Executable",
        "suspicious_urls": "Suspicious URLs"
    }
    
    if isinstance(factor, dict):
        # Extract meaningful info from dict
        contribution = factor.get("contribution", 0)
        count = factor.get("count", 0)
        indicator = factor.get("indicator", "")  # Main key from cvss_calculator
        
        # Also check alternative keys
        name = factor.get("name", factor.get("description", indicator))
        
        # Clean up the indicator name
        if indicator:
            # First try lookup table
            clean_label = indicator_names.get(indicator.lower())
            if not clean_label:
                # Format the indicator key nicely
                clean_label = indicator.replace("_", " ").replace("-", " ").title()
        elif name and isinstance(name, str):
            clean_label = name
        else:
            clean_label = f"Risk Factor ({contribution})"
        
        # Truncate if needed
        if len(clean_label) > 30:
            clean_label = clean_label[:27] + "..."
        
        # Determine risk based on contribution
        if contribution >= 2:
            risk = "critical"
        elif contribution >= 1.5:
            risk = "high"
        elif contribution >= 1:
            risk = "medium"
        else:
            risk = "low"
        
        description = f"Score: {contribution} (×{count})"
        return (clean_label, description, risk)
    
    elif isinstance(factor, str):
        # It's already a string, just clean it
        clean_label = factor.replace("_", " ").replace("-", " ").title()
        if len(clean_label) > 32:
            clean_label = clean_label[:29] + "..."
        
        # Determine risk from keywords
        high_risk_words = ["injection", "malicious", "dangerous", "shellcode", "packed", "obfuscated", "exploit"]
        if any(w in factor.lower() for w in high_risk_words):
            risk = "high"
        else:
            risk = "medium"
        
        return (clean_label, factor, risk)
    
    else:
        return (str(factor)[:30], str(factor), "low")


def _get_capability_label(capability: dict) -> tuple:
    """
    Convert a CAPA capability to a clean label.
    Returns (label, description, risk_level)
    """
    name = capability.get("name", "Unknown Capability")
    namespace = capability.get("namespace", "")
    
    # Clean up the label
    clean_name = name.replace("_", " ").title()
    if len(clean_name) > 28:
        clean_name = clean_name[:25] + "..."
    
    # Determine risk from namespace
    critical_namespaces = ["anti-", "inject", "persist", "exfil", "c2", "evasion"]
    high_namespaces = ["host-interaction", "impact", "collection"]
    
    namespace_lower = namespace.lower()
    if any(ns in namespace_lower for ns in critical_namespaces):
        risk = "critical"
    elif any(ns in namespace_lower for ns in high_namespaces):
        risk = "high"
    else:
        risk = "medium"
    
    description = f"{namespace}: {name}" if namespace else name
    return (clean_name, description, risk)


def check_ollama_available():
    """Check if Ollama service is available."""
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        return response.status_code == 200
    except:
        return False


def generate_ai_report(analysis_data: dict, language: str = "english") -> dict:
    """
    Generate an AI-powered malware intelligence report.
    
    Args:
        analysis_data: The complete analysis data from static analysis
        language: Report language ('english' or 'arabic')
    
    Returns:
        dict containing the report or error message
    """
    logger.info("Starting AI report generation")
    
    # Check Ollama availability
    if not check_ollama_available():
        return {
            "success": False,
            "error": "Ollama service is not available. Please ensure Ollama is running on localhost:11434",
            "report": None
        }
    
    # Prepare analysis summary for LLM
    analysis_summary = _prepare_analysis_summary(analysis_data)
    
    prompt = ENGLISH_ANALYSIS_PROMPT
    
    full_prompt = f"""
{prompt}

--- ANALYSIS INPUT JSON ---
{json.dumps(analysis_summary, indent=2)}
"""

    payload = {
        "model": MODEL_NAME,
        "prompt": full_prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "top_p": 0.9,
            "num_predict": 4096
        }
    }

    try:
        logger.info("Sending request to Ollama")
        response = requests.post(OLLAMA_URL, json=payload, timeout=180)
        
        if response.status_code != 200:
            return {
                "success": False,
                "error": f"Ollama API error: {response.text}",
                "report": None
            }
        
        report_text = response.json().get("response", "")
        
        logger.info("Report generated successfully")
        
        return {
            "success": True,
            "report": report_text,
            "generated_at": datetime.utcnow().isoformat(),
            "model_used": MODEL_NAME,
            "analysis_summary": analysis_summary
        }
        
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Request to Ollama timed out. The analysis may be too complex or Ollama is overloaded.",
            "report": None
        }
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return {
            "success": False,
            "error": str(e),
            "report": None
        }


def _prepare_analysis_summary(data: dict) -> dict:
    """
    Prepare a cleaned summary of analysis data for the LLM.
    
    Args:
        data: Raw analysis data from the file analysis
    
    Returns:
        Cleaned and structured summary dict
    """
    summary = {
        "metadata": {
            "filename": data.get("filename", "Unknown"),
            "file_type": data.get("file_type", "Unknown"),
            "file_size_kb": data.get("file_size_kb", 0),
            "analysis_time": datetime.utcnow().isoformat()
        },
        "static_analysis": {
            "entropy": data.get("entropy", 0),
            "entropy_status": data.get("entropy_status", "Unknown"),
            "hashes": data.get("hashes", {})
        },
        "risk_assessment": {
            "cvss_score": data.get("cvss_score", 0),
            "severity": data.get("severity", "Unknown"),
            "verdict": data.get("verdict", "Unknown"),
            "threat_level": data.get("threat_level", "Unknown"),
            "contributing_factors": data.get("contributing_factors", []),
            "recommendation": data.get("recommendation", "")
        }
    }
    
    # Add file-type specific analysis
    file_type = data.get("file_type", "")
    
    if file_type == "PE":
        summary["pe_analysis"] = _extract_pe_analysis(data)
    elif file_type == "PDF":
        summary["pdf_analysis"] = _extract_pdf_analysis(data)
    elif file_type == "ELF":
        summary["elf_analysis"] = _extract_elf_analysis(data)
    elif file_type == "Office":
        summary["office_analysis"] = _extract_office_analysis(data)
    
    # Add capability analysis if available
    if data.get("capa_analysis") and data["capa_analysis"].get("success"):
        summary["capability_analysis"] = _extract_capa_analysis(data["capa_analysis"])
    
    # Add strings analysis if available
    if data.get("strings_analysis") and not data["strings_analysis"].get("error"):
        summary["strings_analysis"] = _extract_strings_analysis(data["strings_analysis"])
    
    # Add VirusTotal results if available
    if data.get("virustotal") and data["virustotal"].get("found"):
        summary["virustotal_results"] = {
            "detection_ratio": f"{data['virustotal'].get('positives', 0)}/{data['virustotal'].get('total', 0)}",
            "detected_names": data["virustotal"].get("detected_names", [])[:10]  # Top 10
        }
    
    return summary


def _extract_pe_analysis(data: dict) -> dict:
    """Extract relevant PE analysis data."""
    pe = data.get("pe_analysis", {})
    return {
        "architecture": pe.get("architecture", "Unknown"),
        "compilation_time": pe.get("compilation_time", "Unknown"),
        "is_dll": pe.get("is_dll", False),
        "is_driver": pe.get("is_driver", False),
        "is_gui": pe.get("is_gui", False),
        "subsystem": pe.get("subsystem", "Unknown"),
        "sections": pe.get("sections", []),
        "imports": pe.get("imports", {}),
        "suspicious_apis": pe.get("suspicious_apis", []),
        "packer_info": pe.get("die_summary", {})
    }


def _extract_pdf_analysis(data: dict) -> dict:
    """Extract relevant PDF analysis data."""
    pdf = data.get("pdf_analysis", {})
    return {
        "javascript_present": pdf.get("javascript_present", False),
        "embedded_files": pdf.get("embedded_files", 0),
        "auto_actions": pdf.get("auto_actions", False),
        "suspicious_objects": pdf.get("suspicious_objects", []),
        "urls_found": pdf.get("urls_found", []),
        "pdf_version": pdf.get("pdf_version", "Unknown"),
        "obfuscation_score": data.get("pdf_obfuscation", {}).get("score", 0)
    }


def _extract_elf_analysis(data: dict) -> dict:
    """Extract relevant ELF analysis data."""
    elf = data.get("elf_analysis", {})
    hardening = data.get("elf_hardening", {})
    packer = data.get("elf_packer", {})
    
    return {
        "architecture": elf.get("architecture", "Unknown"),
        "elf_type": elf.get("elf_type", "Unknown"),
        "entry_point": elf.get("entry_point", "Unknown"),
        "is_stripped": elf.get("is_stripped", False),
        "libraries": elf.get("libraries", []),
        "suspicious_functions": elf.get("suspicious_functions", []),
        "security_features": {
            "pie": hardening.get("pie", False),
            "relro": hardening.get("relro", "None"),
            "stack_canary": hardening.get("stack_canary", False),
            "nx": hardening.get("nx", False),
            "security_score": hardening.get("security_score", 0)
        },
        "packer_info": {
            "is_packed": packer.get("is_packed", False),
            "packer_name": packer.get("packer_name", None)
        }
    }


def _extract_office_analysis(data: dict) -> dict:
    """Extract relevant Office document analysis data."""
    office = data.get("office_analysis", {})
    macros = data.get("office_macros", {})
    
    return {
        "document_type": office.get("info", {}).get("trid_type", "Unknown"),
        "macros_present": macros.get("has_vba_macros", False) or macros.get("has_xlm_macros", False),
        "auto_execute_macros": macros.get("auto_execute", False),
        "suspicious_keywords": macros.get("suspicious_keywords", []),
        "external_urls": office.get("extracted_urls", []),
        "embedded_objects": office.get("artifacts", []),
        "metadata": office.get("metadata", {}),
        "verdict": office.get("verdict", "Unknown"),
        "reasons": office.get("reasons", [])
    }


def _extract_capa_analysis(capa_data: dict) -> dict:
    """Extract relevant CAPA capability analysis data."""
    capabilities = capa_data.get("capabilities", [])
    
    # Group by namespace/category
    grouped = {}
    for cap in capabilities:
        namespace = cap.get("namespace", "uncategorized")
        if namespace not in grouped:
            grouped[namespace] = []
        grouped[namespace].append(cap.get("name", "Unknown"))
    
    return {
        "total_capabilities": len(capabilities),
        "capabilities_by_category": grouped,
        "high_risk_capabilities": [
            cap.get("name") for cap in capabilities 
            if any(keyword in cap.get("namespace", "").lower() 
                   for keyword in ["injection", "persistence", "evasion", "exfiltration", "c2"])
        ]
    }


def _extract_strings_analysis(strings_data: dict) -> dict:
    """Extract relevant strings analysis data."""
    indicators = strings_data.get("indicators", {})
    
    return {
        "total_strings": strings_data.get("total_strings", 0),
        "interesting_strings": strings_data.get("interesting_strings", [])[:20],  # Top 20
        "urls_found": indicators.get("urls", []),
        "ip_addresses": indicators.get("ips", []),
        "email_addresses": indicators.get("emails", []),
        "registry_keys": indicators.get("registry", []),
        "file_paths": indicators.get("paths", [])
    }


# ===== BEHAVIORAL GRAPH BUILDER =====

def build_relational_graph(analysis_data: dict) -> dict:
    """
    Build a relational graph from static analysis data.
    
    This transforms static analysis indicators into a visual graph structure
    showing relationships between file attributes, capabilities, and behaviors.
    
    Args:
        analysis_data: The complete analysis data from static analysis
    
    Returns:
        dict containing nodes and edges for graph visualization
    """
    nodes = []
    edges = []
    node_id_counter = 0
    
    def add_node(node_type: str, label: str, data: dict = None, risk_level: str = "low") -> str:
        nonlocal node_id_counter
        node_id = f"{node_type}_{node_id_counter}"
        node_id_counter += 1
        nodes.append({
            "id": node_id,
            "type": node_type,
            "label": label,
            "data": data or {},
            "risk_level": risk_level
        })
        return node_id
    
    def add_edge(source: str, target: str, edge_type: str, label: str = None):
        edges.append({
            "id": f"edge_{len(edges)}",
            "source": source,
            "target": target,
            "type": edge_type,
            "label": label or edge_type
        })
    
    # Central file node
    file_type = analysis_data.get("file_type", "Unknown")
    filename = analysis_data.get("filename", "Unknown File")
    severity = analysis_data.get("severity", "None")
    
    # Map severity to risk level
    risk_map = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low", "None": "safe"}
    file_risk = risk_map.get(severity, "low")
    
    central_node = add_node("file", filename, {"type": file_type, "size": analysis_data.get("file_size_kb", 0)}, file_risk)
    
    # Add hash node
    hashes = analysis_data.get("hashes", {})
    if hashes:
        hash_node = add_node("hash", f"SHA256: {hashes.get('sha256', 'N/A')[:16]}...", hashes, "info")
        add_edge(central_node, hash_node, "identified_by", "Hash Values")
    
    # Add entropy node
    entropy = analysis_data.get("entropy", 0)
    if entropy > 0:
        entropy_status = analysis_data.get("entropy_status", "Normal")
        entropy_risk = "high" if entropy > 7.5 else "medium" if entropy > 6 else "low"
        entropy_node = add_node("entropy", f"Entropy: {entropy:.2f}", {"value": entropy, "status": entropy_status}, entropy_risk)
        add_edge(central_node, entropy_node, "has_property", "Entropy Analysis")
    
    # Add CVSS/Risk node
    cvss_score = analysis_data.get("cvss_score", 0)
    if cvss_score:
        verdict = analysis_data.get("verdict", "Unknown")
        cvss_node = add_node("risk", f"CVSS: {cvss_score:.1f}", {"score": cvss_score, "verdict": verdict}, file_risk)
        add_edge(central_node, cvss_node, "risk_assessment", "Risk Score")
    
    # Add contributing factors as nodes with clean labels
    factors = analysis_data.get("contributing_factors", [])
    if factors:
        factor_group = add_node("indicator_group", "Risk Indicators", {"count": len(factors)}, "medium")
        add_edge(central_node, factor_group, "has_indicators", "Risk Factors")
        
        for factor in factors[:10]:  # Limit to top 10
            # Use clean label helper
            clean_label, description, factor_risk = _clean_factor_label(factor)
            factor_node = add_node("indicator", clean_label, {"full_text": description}, factor_risk)
            add_edge(factor_group, factor_node, "includes", "Factor")
    
    # Add file type specific nodes
    if file_type == "PE":
        _add_pe_graph_nodes(analysis_data, central_node, add_node, add_edge)
    elif file_type == "PDF":
        _add_pdf_graph_nodes(analysis_data, central_node, add_node, add_edge)
    elif file_type == "ELF":
        _add_elf_graph_nodes(analysis_data, central_node, add_node, add_edge)
    elif file_type == "Office":
        _add_office_graph_nodes(analysis_data, central_node, add_node, add_edge)
    
    # Add CAPA capabilities
    capa = analysis_data.get("capa_analysis", {})
    if capa.get("success") and capa.get("capabilities"):
        _add_capa_graph_nodes(capa, central_node, add_node, add_edge)
    
    # Add VirusTotal results
    vt = analysis_data.get("virustotal", {})
    if vt.get("found"):
        _add_virustotal_graph_nodes(vt, central_node, add_node, add_edge)
    
    # Add strings indicators
    strings = analysis_data.get("strings_analysis", {})
    if strings and not strings.get("error"):
        _add_strings_graph_nodes(strings, central_node, add_node, add_edge)
    
    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "file_type": file_type,
            "filename": filename,
            "severity": severity,
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }
    }


def _add_pe_graph_nodes(data, central_node, add_node, add_edge):
    """Add PE-specific nodes to the graph."""
    pe = data.get("pe_analysis", {})
    if not pe or pe.get("error"):
        return
    
    # PE info node
    pe_info = add_node("pe_info", "PE Headers", {
        "arch": pe.get("architecture", "Unknown"),
        "subsystem": pe.get("subsystem", "Unknown")
    }, "info")
    add_edge(central_node, pe_info, "has_structure", "PE Analysis")
    
    # Sections
    sections = pe.get("sections", [])
    if sections:
        sections_node = add_node("sections", f"Sections ({len(sections)})", {"count": len(sections)}, "info")
        add_edge(pe_info, sections_node, "contains", "Sections")
        
        for section in sections[:5]:  # Top 5
            section_name = section.get("name", "Unknown")
            section_entropy = section.get("entropy", 0)
            sec_risk = "high" if section_entropy > 7.5 else "medium" if section_entropy > 6.5 else "low"
            sec_node = add_node("section", section_name, section, sec_risk)
            add_edge(sections_node, sec_node, "has_section", section_name)
    
    # Suspicious APIs
    suspicious_apis = pe.get("suspicious_apis", [])
    if suspicious_apis:
        api_group = add_node("api_group", f"Suspicious APIs ({len(suspicious_apis)})", {}, "high")
        add_edge(central_node, api_group, "imports", "Suspicious APIs")
        
        for api in suspicious_apis[:8]:
            api_node = add_node("api", api, {}, "high")
            add_edge(api_group, api_node, "uses", api)
    
    # Packer info
    die = pe.get("die_summary", {})
    if die:
        packer = die.get("packer")
        if packer:
            packer_node = add_node("packer", f"Packer: {packer}", die, "high")
            add_edge(central_node, packer_node, "packed_with", "Packer Detection")


def _add_pdf_graph_nodes(data, central_node, add_node, add_edge):
    """Add PDF-specific nodes to the graph."""
    pdf = data.get("pdf_analysis", {})
    if not pdf or pdf.get("error"):
        return
    
    # PDF structure
    pdf_info = add_node("pdf_info", "PDF Structure", {
        "version": pdf.get("pdf_version", "Unknown")
    }, "info")
    add_edge(central_node, pdf_info, "has_structure", "PDF Analysis")
    
    # JavaScript
    if pdf.get("javascript_present"):
        js_node = add_node("javascript", "JavaScript Detected", {}, "high")
        add_edge(central_node, js_node, "contains", "JavaScript")
    
    # Auto actions
    if pdf.get("auto_actions"):
        auto_node = add_node("auto_action", "Auto-Execute Actions", {}, "high")
        add_edge(central_node, auto_node, "has_behavior", "Auto Actions")
    
    # Embedded files
    embedded = pdf.get("embedded_files", 0)
    if embedded > 0:
        embed_node = add_node("embedded", f"Embedded Files ({embedded})", {"count": embedded}, "medium")
        add_edge(central_node, embed_node, "contains", "Embedded Files")
    
    # Obfuscation
    obf = data.get("pdf_obfuscation", {})
    if obf and obf.get("score", 0) > 0:
        obf_risk = "high" if obf.get("score", 0) > 5 else "medium"
        obf_node = add_node("obfuscation", f"Obfuscation Score: {obf.get('score', 0)}", obf, obf_risk)
        add_edge(central_node, obf_node, "uses", "Obfuscation")


def _add_elf_graph_nodes(data, central_node, add_node, add_edge):
    """Add ELF-specific nodes to the graph."""
    elf = data.get("elf_analysis", {})
    if not elf or elf.get("error"):
        return
    
    # ELF info
    elf_info = add_node("elf_info", "ELF Headers", {
        "arch": elf.get("architecture", "Unknown"),
        "type": elf.get("elf_type", "Unknown")
    }, "info")
    add_edge(central_node, elf_info, "has_structure", "ELF Analysis")
    
    # Security hardening
    hardening = data.get("elf_hardening", {})
    if hardening:
        sec_score = hardening.get("security_score", 0)
        sec_risk = "high" if sec_score < 4 else "medium" if sec_score < 7 else "low"
        sec_node = add_node("security", f"Security Score: {sec_score}/10", hardening, sec_risk)
        add_edge(central_node, sec_node, "security_posture", "Hardening")
    
    # Packer detection
    packer = data.get("elf_packer", {})
    if packer and packer.get("is_packed"):
        packer_name = packer.get("packer_name", "Unknown")
        pack_node = add_node("packer", f"Packed: {packer_name}", packer, "high")
        add_edge(central_node, pack_node, "packed_with", "Packer")
    
    # Suspicious functions
    suspicious = elf.get("suspicious_functions", [])
    if suspicious:
        func_group = add_node("function_group", f"Suspicious Functions ({len(suspicious)})", {}, "medium")
        add_edge(central_node, func_group, "imports", "Suspicious Functions")
        
        for func in suspicious[:8]:
            func_node = add_node("function", func, {}, "medium")
            add_edge(func_group, func_node, "uses", func)


def _add_office_graph_nodes(data, central_node, add_node, add_edge):
    """Add Office document specific nodes to the graph."""
    office = data.get("office_analysis", {})
    if not office or office.get("error"):
        return
    
    # Document info
    doc_type = office.get("info", {}).get("trid_type", "Unknown")
    doc_info = add_node("office_info", f"Office Document", {"type": doc_type}, "info")
    add_edge(central_node, doc_info, "has_structure", "Office Analysis")
    
    # Macros
    macros = data.get("office_macros", {})
    if macros.get("has_vba_macros") or macros.get("has_xlm_macros"):
        macro_risk = "high" if macros.get("auto_execute") else "medium"
        macro_node = add_node("macro", "VBA/XLM Macros", macros, macro_risk)
        add_edge(central_node, macro_node, "contains", "Macros")
        
        # Auto-execute
        if macros.get("auto_execute"):
            auto_node = add_node("auto_execute", "Auto-Execute Macro", {}, "critical")
            add_edge(macro_node, auto_node, "behavior", "Auto-Execute")
        
        # Suspicious keywords
        keywords = macros.get("suspicious_keywords", [])
        if keywords:
            kw_group = add_node("keywords", f"Suspicious Keywords ({len(keywords)})", {}, "high")
            add_edge(macro_node, kw_group, "contains", "Keywords")
    
    # External URLs
    urls = office.get("extracted_urls", [])
    if urls:
        url_risk = "high" if any(u.get("status") == "MALICIOUS" for u in urls) else "medium"
        url_group = add_node("urls", f"External URLs ({len(urls)})", {}, url_risk)
        add_edge(central_node, url_group, "references", "URLs")


def _add_capa_graph_nodes(capa, central_node, add_node, add_edge):
    """Add CAPA capability nodes to the graph with clean labels."""
    capabilities = capa.get("capabilities", [])
    if not capabilities:
        return
    
    # Group capabilities by namespace
    namespaces = {}
    for cap in capabilities:
        ns = cap.get("namespace", "other")
        if ns not in namespaces:
            namespaces[ns] = []
        namespaces[ns].append(cap)
    
    # Create capability overview node
    cap_overview = add_node("capabilities", f"Capabilities ({len(capabilities)})", {"count": len(capabilities)}, "medium")
    add_edge(central_node, cap_overview, "exhibits", "CAPA Analysis")
    
    # Namespace display name mapping for cleaner labels
    ns_display_names = {
        "host-interaction/process/create": "Process Creation",
        "host-interaction/file-system": "File System Ops",
        "host-interaction/process/inject": "Process Injection",
        "host-interaction/registry": "Registry Access",
        "host-interaction/network": "Network Activity",
        "anti-analysis": "Anti-Analysis",
        "persistence": "Persistence",
        "collection": "Data Collection",
        "c2": "Command & Control",
        "defense-evasion": "Defense Evasion",
        "execution": "Code Execution",
        "discovery": "System Discovery",
        "impact": "System Impact"
    }
    
    # Determine risk from namespace
    high_risk_ns = ["anti-analysis", "persistence", "collection", "c2", "defense-evasion", "inject", "execution"]
    
    for ns, caps in list(namespaces.items())[:6]:
        ns_risk = "high" if any(hr in ns.lower() for hr in high_risk_ns) else "medium"
        
        # Find clean display name
        ns_display = ns_display_names.get(ns)
        if not ns_display:
            # Try partial match
            for key, display in ns_display_names.items():
                if key in ns or ns in key:
                    ns_display = display
                    break
            if not ns_display:
                ns_display = ns.split("/")[-1].replace("-", " ").title()
        
        if len(ns_display) > 20:
            ns_display = ns_display[:17] + "..."
        
        ns_node = add_node("namespace", f"{ns_display} ({len(caps)})", {"namespace": ns}, ns_risk)
        add_edge(cap_overview, ns_node, "category", ns_display)
        
        # Add top capabilities in this namespace with clean labels
        for cap in caps[:3]:
            clean_label, description, cap_risk = _get_capability_label(cap)
            cap_node = add_node("capability", clean_label, {"full": description, **cap}, cap_risk)
            add_edge(ns_node, cap_node, "includes", "Capability")


def _add_virustotal_graph_nodes(vt, central_node, add_node, add_edge):
    """Add VirusTotal detection nodes to the graph."""
    positives = vt.get("positives", 0)
    total = vt.get("total", 0)
    
    if total == 0:
        return
    
    detection_ratio = positives / total if total > 0 else 0
    risk = "critical" if detection_ratio > 0.5 else "high" if detection_ratio > 0.2 else "medium" if detection_ratio > 0 else "low"
    
    vt_node = add_node("virustotal", f"VirusTotal: {positives}/{total}", {
        "positives": positives,
        "total": total,
        "ratio": detection_ratio
    }, risk)
    add_edge(central_node, vt_node, "detected_by", "VirusTotal")
    
    # Add top detections
    detected_names = vt.get("detected_names", [])
    if detected_names:
        for name in detected_names[:5]:
            det_node = add_node("detection", name[:30], {}, risk)
            add_edge(vt_node, det_node, "named", name)


def _add_strings_graph_nodes(strings, central_node, add_node, add_edge):
    """Add string analysis nodes to the graph."""
    indicators = strings.get("indicators", {})
    if not indicators:
        return
    
    # URLs
    urls = indicators.get("urls", [])
    if urls:
        url_node = add_node("urls", f"URLs ({len(urls)})", {"urls": urls}, "medium")
        add_edge(central_node, url_node, "contains", "URL Strings")
    
    # IP addresses
    ips = indicators.get("ips", [])
    if ips:
        ip_node = add_node("ips", f"IP Addresses ({len(ips)})", {"ips": ips}, "medium")
        add_edge(central_node, ip_node, "references", "Network Indicators")
    
    # Registry keys
    registry = indicators.get("registry", [])
    if registry:
        reg_node = add_node("registry", f"Registry Keys ({len(registry)})", {"keys": registry}, "high")
        add_edge(central_node, reg_node, "modifies", "Registry Access")


def get_process_explanation(node_id: str, graph_data: dict, facts: dict) -> dict:
    """
    Get AI explanation for a specific node in the graph.
    
    Args:
        node_id: The node ID to explain
        graph_data: The full graph data
        facts: Facts about the node
    
    Returns:
        dict with the explanation
    """
    if not check_ollama_available():
        return {
            "success": False,
            "error": "Ollama service is not available",
            "explanation": None
        }
    
    # Extract node type and context
    node_type = facts.get('type', 'indicator')
    node_label = facts.get('label', 'Unknown')
    node_risk = facts.get('risk', 'medium')
    node_data = facts.get('data', {})
    
    # Build context about the malware
    malware_context = ""
    if graph_data:
        metadata = graph_data.get('metadata', {})
        malware_context = f"""
File being analyzed: {metadata.get('filename', 'Unknown')}
File type: {metadata.get('file_type', 'Unknown')}
Overall severity: {metadata.get('severity', 'Unknown')}
"""
    
    prompt = f"""You are an expert malware analyst explaining a specific indicator found during static analysis.

{malware_context}

## Node Information:
- **Type**: {node_type}
- **Label**: {node_label}
- **Risk Level**: {node_risk}
- **Technical Data**: {json.dumps(node_data, indent=2)}

## Your Task:
Provide a clear, educational explanation for a security analyst about:

1. **What this indicator means**: Explain what "{node_label}" represents in the context of malware analysis

2. **Why it matters**: Describe the security implications - what could an attacker accomplish with this capability?

3. **MITRE ATT&CK context**: If applicable, mention relevant ATT&CK techniques (e.g., T1055 for process injection)

4. **What to investigate**: Suggest what an analyst should look for next related to this indicator

## Format:
Write 3-4 concise paragraphs. Use clear technical language but make it understandable. Be specific to THIS indicator, not generic malware talk.

---
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.4,
                    "num_predict": 800
                }
            },
            timeout=90
        )
        
        if response.status_code != 200:
            return {
                "success": False,
                "error": f"Ollama API error: {response.text}",
                "explanation": None
            }
        
        explanation = response.json().get("response", "")
        return {
            "success": True,
            "explanation": explanation,
            "facts": facts
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "explanation": None
        }
