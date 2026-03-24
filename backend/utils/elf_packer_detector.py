"""
ELF Packer/Obfuscation Detector
Detects packers (UPX, LSD) and obfuscation techniques in ELF binaries
"""

import os
import math
import re

# Try to import pyelftools
try:
    from elftools.elf.elffile import ELFFile
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


# Packer signatures (bytes patterns)
PACKER_SIGNATURES = {
    b"UPX!": "UPX",
    b"UPX0": "UPX",
    b"UPX1": "UPX",
    b"LSD": "LSD",
}

# Suspicious section name substrings (UPX/LSD/protectors)
SUSPICIOUS_SECTION_NAMES = [
    "UPX", "upx", "LSD", "Lsd", ".upx", ".packed", ".pack", "stub", "shim"
]

# Printable string pattern
PRINTABLE_RE = re.compile(rb'[\x20-\x7E]{4,}')


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data"""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in freq if c)


def detect_packer_signatures(raw_data: bytes) -> list:
    """
    Detect packer signatures in raw binary data
    
    Args:
        raw_data (bytes): Raw file content
        
    Returns:
        list: List of detected packer indicators
    """
    indicators = []
    lower_data = raw_data.lower()
    
    for sig, packer_name in PACKER_SIGNATURES.items():
        try:
            if sig in raw_data:
                indicators.append({
                    "type": "signature",
                    "packer": packer_name,
                    "description": f"{packer_name} signature detected"
                })
            # Also check case-insensitive for alpha signatures
            elif sig.isalpha() and sig.lower() in lower_data:
                indicators.append({
                    "type": "signature",
                    "packer": packer_name,
                    "description": f"{packer_name} signature detected (case-insensitive)"
                })
        except Exception:
            pass
    
    return indicators


def detect_suspicious_sections(file_path: str) -> list:
    """
    Detect suspicious section names associated with packers
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        list: List of suspicious sections
    """
    if not PYELFTOOLS_AVAILABLE:
        return []
    
    indicators = []
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                section_name = (section.name or "").lower()
                for substr in SUSPICIOUS_SECTION_NAMES:
                    if substr.lower() in section_name:
                        indicators.append({
                            "type": "suspicious_section",
                            "section": section.name,
                            "description": f"Suspicious section name: {section.name}"
                        })
                        break
    except Exception:
        pass
    
    return indicators


def detect_stripped_symbols(file_path: str) -> dict:
    """
    Detect if symbol tables are stripped
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Symbol stripping analysis
    """
    if not PYELFTOOLS_AVAILABLE:
        return {"stripped": False, "reason": "pyelftools not available"}
    
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            
            dynsym = elf.get_section_by_name('.dynsym')
            symtab = elf.get_section_by_name('.symtab')
            
            dynsym_count = dynsym.num_symbols() if dynsym and hasattr(dynsym, 'num_symbols') else 0
            symtab_count = symtab.num_symbols() if symtab and hasattr(symtab, 'num_symbols') else 0
            
            if dynsym_count == 0 and symtab_count == 0:
                return {
                    "stripped": True,
                    "description": "All symbol tables stripped",
                    "dynsym_count": dynsym_count,
                    "symtab_count": symtab_count
                }
            
            return {
                "stripped": False,
                "dynsym_count": dynsym_count,
                "symtab_count": symtab_count
            }
            
    except Exception as e:
        return {"stripped": False, "error": str(e)}


def detect_segment_expansion(file_path: str) -> list:
    """
    Detect segments with suspicious size expansion (common in unpacking stubs)
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        list: List of suspicious segment expansions
    """
    if not PYELFTOOLS_AVAILABLE:
        return []
    
    indicators = []
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                h = seg.header
                p_type = h.get("p_type", None)
                
                # Check PT_LOAD segments
                if p_type == 1 or str(p_type) == "PT_LOAD":
                    p_filesz = h.get("p_filesz", 0)
                    p_memsz = h.get("p_memsz", 0)
                    p_offset = h.get("p_offset", 0)
                    
                    # Large PT_LOAD at file start
                    if p_offset == 0 and p_filesz > 1_000_000:
                        indicators.append({
                            "type": "large_load_segment",
                            "description": f"Large PT_LOAD at file start ({p_filesz} bytes)"
                        })
                    
                    # Segment expands significantly (4x or more)
                    if p_filesz > 0 and p_memsz > p_filesz * 4:
                        indicators.append({
                            "type": "segment_expansion",
                            "file_size": p_filesz,
                            "memory_size": p_memsz,
                            "ratio": round(p_memsz / p_filesz, 2),
                            "description": f"Segment expands {p_filesz} -> {p_memsz} bytes (unpacking indicator)"
                        })
    except Exception:
        pass
    
    return indicators


def detect_high_entropy_regions(file_path: str, window_size: int = 4096, threshold: float = 7.8) -> list:
    """
    Detect high-entropy regions lacking printable strings (packed data)
    
    Args:
        file_path (str): Path to file
        window_size (int): Size of analysis window
        threshold (float): Entropy threshold
        
    Returns:
        list: List of high-entropy regions
    """
    indicators = []
    try:
        with open(file_path, "rb") as f:
            data = f.read(3_000_000)  # Scan first 3MB
        
        for i in range(0, max(0, len(data) - window_size), window_size):
            chunk = data[i:i + window_size]
            entropy = shannon_entropy(chunk)
            
            if entropy > threshold and not PRINTABLE_RE.search(chunk):
                indicators.append({
                    "type": "high_entropy_region",
                    "offset": f"0x{i:x}",
                    "entropy": round(entropy, 2),
                    "description": f"High-entropy packed region at 0x{i:x} (entropy={entropy:.2f})"
                })
                # Only report first occurrence to avoid spam
                break
                
    except Exception:
        pass
    
    return indicators


def detect_text_entropy_anomaly(file_path: str) -> dict:
    """
    Detect high .text section entropy with few dynamic symbols
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Anomaly detection result
    """
    if not PYELFTOOLS_AVAILABLE:
        return {"anomaly": False}
    
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            
            text = elf.get_section_by_name('.text')
            dynsym = elf.get_section_by_name('.dynsym')
            
            if text:
                try:
                    text_data = text.data()
                    text_entropy = shannon_entropy(text_data)
                    dynsym_count = dynsym.num_symbols() if dynsym and hasattr(dynsym, 'num_symbols') else 0
                    
                    if text_entropy > 7.3 and dynsym_count < 5:
                        return {
                            "anomaly": True,
                            "text_entropy": round(text_entropy, 4),
                            "dynsym_count": dynsym_count,
                            "description": "High .text entropy with minimal dynamic symbols (packing indicator)"
                        }
                except Exception:
                    pass
        
        return {"anomaly": False}
        
    except Exception:
        return {"anomaly": False}


def get_elf_packer_analysis(file_path: str) -> dict:
    """
    Perform comprehensive packer/obfuscation analysis
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Packer analysis results
    """
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    
    # Read raw file for signature scanning
    try:
        with open(file_path, "rb") as f:
            raw_data = f.read(5_000_000)  # Read first 5MB
    except Exception as e:
        return {"error": f"Cannot read file: {str(e)}"}
    
    indicators = []
    packers_detected = set()
    
    # 1. Check packer signatures
    sig_indicators = detect_packer_signatures(raw_data)
    for ind in sig_indicators:
        indicators.append(ind)
        if "packer" in ind:
            packers_detected.add(ind["packer"])
    
    # 2. Check suspicious sections
    section_indicators = detect_suspicious_sections(file_path)
    indicators.extend(section_indicators)
    
    # 3. Check stripped symbols
    stripped = detect_stripped_symbols(file_path)
    if stripped.get("stripped"):
        indicators.append({
            "type": "stripped_symbols",
            "description": stripped.get("description", "Symbol tables stripped")
        })
    
    # 4. Check segment expansion
    expansion_indicators = detect_segment_expansion(file_path)
    indicators.extend(expansion_indicators)
    
    # 5. Check high-entropy regions
    entropy_indicators = detect_high_entropy_regions(file_path)
    indicators.extend(entropy_indicators)
    
    # 6. Check .text entropy anomaly
    text_anomaly = detect_text_entropy_anomaly(file_path)
    if text_anomaly.get("anomaly"):
        indicators.append({
            "type": "text_entropy_anomaly",
            "description": text_anomaly.get("description", "High .text entropy anomaly")
        })
    
    # Deduplicate indicators by description
    seen = set()
    unique_indicators = []
    for ind in indicators:
        desc = ind.get("description", "")
        if desc not in seen:
            seen.add(desc)
            unique_indicators.append(ind)
    
    # Determine if packed
    is_packed = len(packers_detected) > 0 or len(indicators) >= 2
    
    return {
        "is_packed": is_packed,
        "packers_detected": list(packers_detected),
        "indicators": unique_indicators,
        "indicator_count": len(unique_indicators),
        "stripped_info": stripped
    }
