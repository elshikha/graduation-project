"""
ELF Security Hardening Analyzer
Analyzes security hardening features in ELF binaries:
- RELRO (Relocation Read-Only)
- PIE (Position Independent Executable)
- NX (Non-Executable stack)
- Stack Canary
- FORTIFY_SOURCE
"""

import os

# Try to import pyelftools
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


def detect_relro(elf) -> dict:
    """
    Detect RELRO (Relocation Read-Only) protection level
    
    Full RELRO: GNU_RELRO segment + BIND_NOW
    Partial RELRO: GNU_RELRO segment only
    
    Args:
        elf: ELFFile object
        
    Returns:
        dict: RELRO detection result
    """
    has_gnu_relro = False
    bind_now = False
    
    # Check for GNU_RELRO segment
    try:
        for seg in elf.iter_segments():
            p_type = seg.header.get("p_type", None)
            if p_type == 0x6474e552 or str(p_type) == "PT_GNU_RELRO":
                has_gnu_relro = True
                break
    except Exception:
        pass
    
    # Check for BIND_NOW in dynamic section
    try:
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    d_tag = tag.entry.get('d_tag', None)
                    if d_tag in ('DT_BIND_NOW', 24, 0x6ffffffb):
                        bind_now = True
                        break
                    # Also check DT_FLAGS for DF_BIND_NOW
                    if d_tag in ('DT_FLAGS', 30):
                        if tag.entry.get('d_val', 0) & 0x8:  # DF_BIND_NOW
                            bind_now = True
                            break
                    # Check DT_FLAGS_1 for DF_1_NOW
                    if d_tag in ('DT_FLAGS_1', 0x6ffffffb):
                        if tag.entry.get('d_val', 0) & 0x1:  # DF_1_NOW
                            bind_now = True
                            break
    except Exception:
        pass
    
    if has_gnu_relro and bind_now:
        return {
            "level": "Full",
            "has_gnu_relro": True,
            "has_bind_now": True,
            "description": "Full RELRO - GOT is read-only, lazy binding disabled"
        }
    elif has_gnu_relro:
        return {
            "level": "Partial",
            "has_gnu_relro": True,
            "has_bind_now": False,
            "description": "Partial RELRO - Some sections read-only, GOT still writable"
        }
    else:
        return {
            "level": "None",
            "has_gnu_relro": False,
            "has_bind_now": False,
            "description": "No RELRO - GOT is fully writable"
        }


def detect_pie(elf) -> dict:
    """
    Detect PIE (Position Independent Executable)
    
    PIE binaries have e_type = ET_DYN (shared object)
    
    Args:
        elf: ELFFile object
        
    Returns:
        dict: PIE detection result
    """
    try:
        e_type = elf.header.get('e_type', '')
        is_pie = (e_type == 'ET_DYN')
        
        return {
            "enabled": is_pie,
            "e_type": str(e_type),
            "description": "Position Independent Executable - ASLR enabled" if is_pie else
                          "Not PIE - Fixed base address, vulnerable to ROP"
        }
    except Exception as e:
        return {"enabled": False, "error": str(e)}


def detect_nx(elf) -> dict:
    """
    Detect NX (Non-Executable) stack protection
    
    Checks GNU_STACK segment permissions
    
    Args:
        elf: ELFFile object
        
    Returns:
        dict: NX detection result
    """
    try:
        for seg in elf.iter_segments():
            p_type = seg.header.get("p_type", None)
            if p_type == 0x6474e551 or str(p_type) == "PT_GNU_STACK":
                p_flags = seg.header.get("p_flags", 0)
                # Check if executable flag is set
                is_executable = bool(p_flags & 0x1)
                
                return {
                    "enabled": not is_executable,
                    "stack_executable": is_executable,
                    "flags": p_flags,
                    "description": "NX disabled - Stack is executable (dangerous)" if is_executable else
                                  "NX enabled - Stack is non-executable"
                }
        
        # No GNU_STACK segment - assume NX enabled (modern default)
        return {
            "enabled": True,
            "stack_executable": False,
            "description": "NX enabled (no PT_GNU_STACK, modern default)"
        }
        
    except Exception as e:
        return {"enabled": True, "error": str(e)}


def detect_stack_canary(elf) -> dict:
    """
    Detect Stack Canary (Stack Protector) presence
    
    Looks for __stack_chk_fail symbol
    
    Args:
        elf: ELFFile object
        
    Returns:
        dict: Stack canary detection result
    """
    try:
        canary_symbols = ["__stack_chk_fail", "__stack_chk_guard"]
        found_symbols = []
        
        for section_name in [".dynsym", ".symtab"]:
            section = elf.get_section_by_name(section_name)
            if not section:
                continue
            
            try:
                for sym in section.iter_symbols():
                    sym_name = sym.name or ""
                    for canary_sym in canary_symbols:
                        if canary_sym in sym_name:
                            found_symbols.append(sym_name)
            except Exception:
                pass
        
        has_canary = len(found_symbols) > 0
        
        return {
            "enabled": has_canary,
            "symbols_found": found_symbols,
            "description": "Stack canary present - Buffer overflow protection" if has_canary else
                          "No stack canary - Vulnerable to buffer overflows"
        }
        
    except Exception as e:
        return {"enabled": False, "error": str(e)}


def detect_fortify(elf) -> dict:
    """
    Detect FORTIFY_SOURCE presence
    
    Looks for *_chk function variants (e.g., memcpy_chk, strcpy_chk)
    
    Args:
        elf: ELFFile object
        
    Returns:
        dict: FORTIFY detection result
    """
    try:
        fortify_functions = []
        
        for section_name in [".dynsym", ".symtab"]:
            section = elf.get_section_by_name(section_name)
            if not section:
                continue
            
            try:
                for sym in section.iter_symbols():
                    sym_name = sym.name or ""
                    if sym_name.endswith("_chk") and not sym_name.startswith("__stack"):
                        fortify_functions.append(sym_name)
            except Exception:
                pass
        
        # Deduplicate
        fortify_functions = list(set(fortify_functions))
        has_fortify = len(fortify_functions) > 0
        
        return {
            "enabled": has_fortify,
            "functions_found": fortify_functions[:20],  # Limit output
            "function_count": len(fortify_functions),
            "description": "FORTIFY_SOURCE enabled - Runtime buffer overflow checks" if has_fortify else
                          "FORTIFY_SOURCE not detected"
        }
        
    except Exception as e:
        return {"enabled": False, "error": str(e)}


def detect_rpath(elf) -> dict:
    """
    Detect RPATH/RUNPATH presence (can be a security concern)
    
    Args:
        elf: ELFFile object
        
    Returns:
        dict: RPATH detection result
    """
    try:
        rpath = None
        runpath = None
        
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    d_tag = str(tag.entry.get('d_tag', ''))
                    if 'RPATH' in d_tag:
                        rpath = tag.rpath if hasattr(tag, 'rpath') else str(tag.entry.get('d_val', ''))
                    elif 'RUNPATH' in d_tag:
                        runpath = tag.runpath if hasattr(tag, 'runpath') else str(tag.entry.get('d_val', ''))
        
        has_rpath = rpath is not None or runpath is not None
        
        result = {
            "has_rpath": rpath is not None,
            "has_runpath": runpath is not None,
            "rpath": rpath,
            "runpath": runpath
        }
        
        if has_rpath:
            result["description"] = f"Custom library paths set - potential DLL hijacking risk"
        else:
            result["description"] = "No RPATH/RUNPATH - using standard library paths"
        
        return result
        
    except Exception as e:
        return {"has_rpath": False, "has_runpath": False, "error": str(e)}


def get_elf_hardening_analysis(file_path: str) -> dict:
    """
    Perform comprehensive security hardening analysis
    
    Args:
        file_path (str): Path to ELF file
        
    Returns:
        dict: Complete hardening analysis results
    """
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    
    if not PYELFTOOLS_AVAILABLE:
        return {"error": "pyelftools not installed. Install with: pip install pyelftools"}
    
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            
            # Collect all hardening checks
            relro = detect_relro(elf)
            pie = detect_pie(elf)
            nx = detect_nx(elf)
            canary = detect_stack_canary(elf)
            fortify = detect_fortify(elf)
            rpath = detect_rpath(elf)
            
            # Calculate security score (0-10)
            score = 0
            max_score = 10
            
            if relro.get("level") == "Full":
                score += 2.5
            elif relro.get("level") == "Partial":
                score += 1.0
            
            if pie.get("enabled"):
                score += 2.5
            
            if nx.get("enabled"):
                score += 2.5
            
            if canary.get("enabled"):
                score += 1.5
            
            if fortify.get("enabled"):
                score += 1.0
            
            # Determine overall status
            if score >= 8:
                status = "Well Hardened"
                status_color = "green"
            elif score >= 5:
                status = "Partially Hardened"
                status_color = "yellow"
            else:
                status = "Poorly Hardened"
                status_color = "red"
            
            return {
                "relro": relro,
                "pie": pie,
                "nx": nx,
                "stack_canary": canary,
                "fortify": fortify,
                "rpath": rpath,
                "security_score": round(score, 1),
                "max_score": max_score,
                "status": status,
                "status_color": status_color,
                "summary": {
                    "RELRO": relro.get("level", "Unknown"),
                    "PIE": "Enabled" if pie.get("enabled") else "Disabled",
                    "NX": "Enabled" if nx.get("enabled") else "Disabled",
                    "Canary": "Present" if canary.get("enabled") else "Not found",
                    "Fortify": "Present" if fortify.get("enabled") else "Not found"
                }
            }
            
    except Exception as e:
        return {"error": f"Failed to analyze ELF hardening: {str(e)}"}
