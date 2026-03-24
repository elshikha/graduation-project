"""
ELF (Executable and Linkable Format) Analyzer
Provides comprehensive analysis of Linux/Unix ELF binaries
Includes header parsing, section analysis, symbol extraction, and import detection
"""

import os
import math
import re
import struct

# Try to import pyelftools
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False
    print("[WARNING] pyelftools not installed. ELF analysis will be limited.")
    print("         Install with: pip install pyelftools")


# Dangerous imports commonly used by malware
DANGEROUS_IMPORTS = {
    "system", "popen", "execl", "execv", "execve", "execvp", "fork", "vfork", "clone", "ptrace",
    "mprotect", "dlopen", "dlsym", "socket", "connect", "accept", "bind", "listen",
    "send", "recv", "sendto", "recvfrom", "open", "fopen", "remove", "unlink", "chmod", "chown"
}

# URL pattern for extraction
URL_RE = re.compile(rb'\b((?:https?|ftp)://[^\s\'"<>]+)', re.IGNORECASE)


def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data
    
    Args:
        data (bytes): Byte data to analyze
        
    Returns:
        float: Entropy value (0-8)
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in freq if c)


def p_type_to_str(p_type: int) -> str:
    """Convert program header type to string"""
    types = {
        0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE",
        5: "PT_SHLIB", 6: "PT_PHDR", 7: "PT_TLS", 0x6474e550: "PT_GNU_EH_FRAME",
        0x6474e551: "PT_GNU_STACK", 0x6474e552: "PT_GNU_RELRO"
    }
    return types.get(p_type, f"0x{p_type:x}")


def p_flags_to_str(flags: int) -> str:
    """Convert segment flags to readable string"""
    return "".join(x for bit, x in ((4, "R"), (2, "W"), (1, "E")) if flags & bit) or "-"


def hex_bytes(data: bytes) -> str:
    """Convert bytes to hex string"""
    return " ".join(f"{b:02x}" for b in data)


def precheck_elf_sanity(file_path: str) -> dict:
    """
    Perform basic ELF sanity check before full parsing
    
    Args:
        file_path (str): Path to file
        
    Returns:
        dict: Sanity check results
    """
    raw = b""
    issues = []
    
    try:
        with open(file_path, "rb") as f:
            raw = f.read(64)
    except Exception as e:
        return {"is_elf": False, "issues": [f"Cannot read file: {e}"], "raw": raw}
    
    if len(raw) < 16 or raw[:4] != b"\x7fELF":
        return {"is_elf": False, "issues": ["Magic mismatch (not ELF)"], "raw": raw}
    
    ei_class, ei_data, ei_ver = raw[4], raw[5], raw[6]
    
    if ei_class not in (1, 2):
        issues.append(f"Invalid EI_CLASS: 0x{ei_class:02x}")
    if ei_data not in (1, 2):
        issues.append(f"Invalid EI_DATA: 0x{ei_data:02x}")
    if ei_ver != 1:
        issues.append(f"Invalid EI_VERSION: 0x{ei_ver:02x}")
    
    is_64 = (ei_class == 2)
    little = (ei_data == 1)
    e_phnum = None
    e_shoff = None
    
    try:
        if is_64:
            if len(raw) >= 58:
                e_phnum = struct.unpack("<H" if little else ">H", raw[56:58])[0]
            if len(raw) >= 48:
                e_shoff = struct.unpack("<Q" if little else ">Q", raw[40:48])[0]
        else:
            if len(raw) >= 46:
                e_phnum = struct.unpack("<H" if little else ">H", raw[44:46])[0]
            if len(raw) >= 36:
                e_shoff = struct.unpack("<I" if little else ">I", raw[32:36])[0]
    except Exception:
        pass
    
    if e_phnum is not None and e_phnum > 2000:
        issues.append(f"Extreme program header count (e_phnum={e_phnum}) – likely malformed ELF")
    
    return {
        "is_elf": True,
        "issues": issues,
        "is_64": is_64,
        "little_endian": little,
        "e_phnum": e_phnum,
        "e_shoff": e_shoff,
        "raw": raw
    }


def extract_urls(file_path: str, max_bytes: int = 3_000_000) -> list:
    """
    Extract URLs from binary file
    
    Args:
        file_path (str): Path to file
        max_bytes (int): Maximum bytes to scan
        
    Returns:
        list: List of extracted URLs
    """
    urls = set()
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
        for m in URL_RE.findall(data):
            try:
                urls.add(m.decode("utf-8", errors="ignore"))
            except Exception:
                pass
    except Exception:
        pass
    return sorted(urls)


def find_embedded_payloads(file_path: str, max_scan: int = 5_000_000) -> list:
    """
    Detect embedded payloads (ELF, PE, ZIP) within the file
    
    Args:
        file_path (str): Path to file
        max_scan (int): Maximum bytes to scan
        
    Returns:
        list: List of detected embedded payloads
    """
    embedded = []
    signatures = {
        b'\x7fELF': 'ELF',
        b'MZ\x90': 'PE',
        b'PK\x03\x04': 'ZIP'
    }
    
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_scan)
        
        for sig, name in signatures.items():
            idx = 0
            while True:
                i = data.find(sig, idx)
                if i == -1:
                    break
                # Skip first occurrence for ELF (the file itself)
                if name == 'ELF' and i == 0:
                    idx = i + 1
                    continue
                embedded.append({
                    'type': name,
                    'offset': f"0x{i:x}",
                    'description': f"Embedded {name} at offset 0x{i:x}"
                })
                idx = i + 1
    except Exception:
        pass
    
    return embedded


def analyze_elf_header(file_path: str) -> dict:
    """
    Analyze ELF file header
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: ELF header information
    """
    if not PYELFTOOLS_AVAILABLE:
        return {"error": "pyelftools not installed. Install with: pip install pyelftools"}
    
    # Sanity check first
    sanity = precheck_elf_sanity(file_path)
    if not sanity["is_elf"]:
        return {
            "error": "Not a valid ELF file",
            "issues": sanity.get("issues", []),
            "magic": hex_bytes(sanity.get("raw", b"")[:16])
        }
    
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            ident = elf['e_ident']
            header = elf.header
            
            # Extract header information
            elf_info = {
                "magic": hex_bytes(sanity["raw"][:16]),
                "class": ident['EI_CLASS'].replace('ELFCLASS', 'ELF'),
                "data": "little endian" if ident["EI_DATA"] == "ELFDATA2LSB" else "big endian",
                "version": str(ident['EI_VERSION']),
                "os_abi": str(ident.get('EI_OSABI', 'UNIX - System V')),
                "abi_version": ident.get('EI_ABIVERSION', 0),
                "type": str(header['e_type']),
                "machine": str(header['e_machine']),
                "entry_point": f"0x{header['e_entry']:x}",
                "program_header_offset": header['e_phoff'],
                "section_header_offset": header['e_shoff'],
                "flags": f"0x{header.get('e_flags', 0):x}",
                "header_size": header.get('e_ehsize', 0),
                "program_header_size": header.get('e_phentsize', 0),
                "program_header_count": header.get('e_phnum', 0),
                "section_header_size": header.get('e_shentsize', 0),
                "section_header_count": header.get('e_shnum', 0),
                "string_table_index": header.get('e_shstrndx', 0),
                "sanity_issues": sanity.get("issues", [])
            }
            
            return elf_info
            
    except Exception as e:
        return {"error": f"Failed to parse ELF header: {str(e)}"}


def analyze_elf_sections(file_path: str) -> dict:
    """
    Analyze ELF sections with entropy calculation
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Section analysis results
    """
    if not PYELFTOOLS_AVAILABLE:
        return {"error": "pyelftools not installed"}
    
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            sections = []
            high_entropy_sections = []
            
            for i, section in enumerate(elf.iter_sections()):
                h = section.header
                
                # Calculate section entropy
                try:
                    data = section.data() if hasattr(section, 'data') and section.data_size > 0 else b""
                    entropy = round(shannon_entropy(data), 4) if data else 0.0
                except Exception:
                    entropy = 0.0
                
                section_info = {
                    "index": i,
                    "name": section.name or "<unnamed>",
                    "type": str(h.get("sh_type", "")),
                    "address": f"0x{h.get('sh_addr', 0):08x}",
                    "offset": f"0x{h.get('sh_offset', 0):06x}",
                    "size": h.get("sh_size", 0),
                    "entry_size": h.get("sh_entsize", 0),
                    "flags": h.get("sh_flags", 0),
                    "entropy": entropy
                }
                sections.append(section_info)
                
                # Track high entropy sections
                if entropy > 7.0:
                    high_entropy_sections.append({
                        "name": section.name,
                        "entropy": entropy
                    })
            
            return {
                "sections": sections,
                "section_count": len(sections),
                "high_entropy_sections": high_entropy_sections
            }
            
    except Exception as e:
        return {"error": f"Failed to analyze sections: {str(e)}"}


def analyze_elf_segments(file_path: str) -> dict:
    """
    Analyze ELF program headers (segments)
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Segment analysis results
    """
    if not PYELFTOOLS_AVAILABLE:
        return {"error": "pyelftools not installed"}
    
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            segments = []
            rwx_segments = []
            interpreter = None
            
            for i, seg in enumerate(elf.iter_segments()):
                h = seg.header
                p_type = h.get("p_type", 0)
                p_flags = h.get("p_flags", 0)
                
                segment_info = {
                    "index": i,
                    "type": p_type_to_str(p_type) if isinstance(p_type, int) else str(p_type),
                    "offset": f"0x{h.get('p_offset', 0):08x}",
                    "virtual_address": f"0x{h.get('p_vaddr', 0):016x}",
                    "physical_address": f"0x{h.get('p_paddr', 0):016x}",
                    "file_size": h.get("p_filesz", 0),
                    "memory_size": h.get("p_memsz", 0),
                    "flags": p_flags_to_str(p_flags),
                    "alignment": f"0x{h.get('p_align', 0):x}"
                }
                segments.append(segment_info)
                
                # Detect RWX segments (suspicious)
                if (p_flags & 4) and (p_flags & 2) and (p_flags & 1):
                    rwx_segments.append(segment_info)
                
                # Extract interpreter
                if p_type == 3 or str(p_type) == "PT_INTERP":
                    try:
                        data = seg.data()
                        if data:
                            interpreter = data.decode("ascii", errors="ignore").strip("\x00")
                    except Exception:
                        pass
            
            return {
                "segments": segments,
                "segment_count": len(segments),
                "rwx_segments": rwx_segments,
                "has_rwx": len(rwx_segments) > 0,
                "interpreter": interpreter
            }
            
    except Exception as e:
        return {"error": f"Failed to analyze segments: {str(e)}"}


def analyze_elf_symbols(file_path: str) -> dict:
    """
    Analyze ELF symbol tables
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Symbol analysis results
    """
    if not PYELFTOOLS_AVAILABLE:
        return {"error": "pyelftools not installed"}
    
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            
            symbols = {"dynsym": [], "symtab": []}
            all_imports = set()
            dangerous_imports = set()
            
            for section_name in [".dynsym", ".symtab"]:
                section = elf.get_section_by_name(section_name)
                if section and isinstance(section, SymbolTableSection):
                    key = section_name.replace(".", "")
                    for sym in section.iter_symbols():
                        name = sym.name or ""
                        if name:
                            all_imports.add(name)
                            if name in DANGEROUS_IMPORTS:
                                dangerous_imports.add(name)
                        
                        # Only store first 100 symbols per table
                        if len(symbols[key]) < 100:
                            st = sym.entry
                            symbols[key].append({
                                "name": name,
                                "value": f"0x{st.get('st_value', 0):08x}",
                                "size": st.get("st_size", 0),
                                "type": str(st.get("st_info", {}).get("type", "")),
                                "bind": str(st.get("st_info", {}).get("bind", "")),
                                "section_index": st.get("st_shndx", 0)
                            })
            
            no_symbols = len(symbols["dynsym"]) == 0 and len(symbols["symtab"]) == 0
            
            return {
                "dynsym_count": len(symbols["dynsym"]),
                "symtab_count": len(symbols["symtab"]),
                "dynsym": symbols["dynsym"][:50],  # Limit for response size
                "symtab": symbols["symtab"][:50],
                "no_symbols": no_symbols,
                "suspicious_imports": sorted(dangerous_imports),
                "import_count": len(all_imports)
            }
            
    except Exception as e:
        return {"error": f"Failed to analyze symbols: {str(e)}"}


def detect_syscalls(file_path: str) -> dict:
    """
    Detect raw syscall patterns in .text section
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Syscall detection results
    """
    if not PYELFTOOLS_AVAILABLE:
        return {"error": "pyelftools not installed"}
    
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            text_section = elf.get_section_by_name('.text')
            
            syscalls = []
            if text_section:
                try:
                    data = text_section.data()
                    if b'\x0f\x05' in data:
                        syscalls.append({"type": "syscall", "pattern": "0f 05", "description": "x86_64 syscall instruction"})
                    if b'\xcd\x80' in data:
                        syscalls.append({"type": "int 0x80", "pattern": "cd 80", "description": "x86 legacy interrupt"})
                except Exception:
                    pass
            
            return {
                "syscalls_detected": syscalls,
                "has_raw_syscalls": len(syscalls) > 0
            }
            
    except Exception as e:
        return {"error": f"Failed to detect syscalls: {str(e)}"}


def get_comprehensive_elf_analysis(file_path: str) -> dict:
    """
    Perform comprehensive ELF analysis combining all components
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Complete ELF analysis results
    """
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    
    # Get file size
    file_size = os.path.getsize(file_path)
    
    # Calculate whole-file entropy
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        file_entropy = round(shannon_entropy(content), 4)
    except Exception:
        file_entropy = 0.0
    
    # Collect all analysis results
    analysis = {
        "file_size": file_size,
        "file_entropy": file_entropy,
        "entropy_status": "High (Possibly packed/encrypted)" if file_entropy >= 7.5 else
                         "Medium (Compressed or mixed content)" if file_entropy >= 6.0 else
                         "Low (Plain binary)"
    }
    
    # Header analysis
    header = analyze_elf_header(file_path)
    if "error" not in header:
        analysis["header"] = header
    else:
        analysis["header_error"] = header.get("error")
    
    # Section analysis
    sections = analyze_elf_sections(file_path)
    if "error" not in sections:
        analysis["sections"] = sections
    else:
        analysis["sections_error"] = sections.get("error")
    
    # Segment analysis
    segments = analyze_elf_segments(file_path)
    if "error" not in segments:
        analysis["segments"] = segments
        analysis["interpreter"] = segments.get("interpreter")
        analysis["has_rwx_segments"] = segments.get("has_rwx", False)
    else:
        analysis["segments_error"] = segments.get("error")
    
    # Symbol analysis
    symbols = analyze_elf_symbols(file_path)
    if "error" not in symbols:
        analysis["symbols"] = symbols
        analysis["suspicious_imports"] = symbols.get("suspicious_imports", [])
        analysis["no_symbols"] = symbols.get("no_symbols", False)
    else:
        analysis["symbols_error"] = symbols.get("error")
    
    # Syscall detection
    syscalls = detect_syscalls(file_path)
    if "error" not in syscalls:
        analysis["syscalls"] = syscalls
    
    # URL extraction
    urls = extract_urls(file_path)
    analysis["urls"] = urls
    analysis["url_count"] = len(urls)
    
    # Embedded payload detection
    embedded = find_embedded_payloads(file_path)
    analysis["embedded_payloads"] = embedded
    analysis["has_embedded_payloads"] = len(embedded) > 0
    
    return analysis
