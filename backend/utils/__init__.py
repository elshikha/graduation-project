"""
Backend Utilities Package
"""

from .file_detector import detect_file_type, is_supported_type, get_file_info
from .hash_calculator import (
    calculate_md5, 
    calculate_sha1, 
    calculate_sha256, 
    calculate_sha512,
    calculate_all_hashes,
    verify_hash
)
from .file_analyzer import (
    calculate_file_entropy,
    get_file_timestamps,
    calculate_blake2b,
    analyze_pe_header,
    get_comprehensive_file_info,
    search_file_by_hash
)
from .pdf_analyzer import (
    analyze_pdf_structure,
    extract_pdf_metadata,
    get_comprehensive_pdf_analysis,
    check_pdf_header
)
from .virustotal_scanner import (
    scan_file_hash,
    VTScanner
)
from .strings_analyzer import (
    analyze_strings,
    check_urls_with_virustotal
)
from .elf_analyzer import (
    get_comprehensive_elf_analysis,
    analyze_elf_header,
    analyze_elf_sections,
    analyze_elf_segments,
    analyze_elf_symbols
)
from .elf_packer_detector import get_elf_packer_analysis
from .elf_hardening_analyzer import get_elf_hardening_analysis
from .office_analyzer import (
    get_comprehensive_office_analysis,
    get_office_macro_analysis,
    get_office_url_analysis
)

__all__ = [
    'detect_file_type',
    'is_supported_type',
    'get_file_info',
    'calculate_md5',
    'calculate_sha1',
    'calculate_sha256',
    'calculate_sha512',
    'calculate_all_hashes',
    'verify_hash',
    'calculate_file_entropy',
    'get_file_timestamps',
    'calculate_blake2b',
    'analyze_pe_header',
    'get_comprehensive_file_info',
    'search_file_by_hash',
    'analyze_pdf_structure',
    'extract_pdf_metadata',
    'get_comprehensive_pdf_analysis',
    'check_pdf_header',
    'scan_file_hash',
    'VTScanner',
    'analyze_strings',
    'check_urls_with_virustotal',
    # ELF analysis
    'get_comprehensive_elf_analysis',
    'analyze_elf_header',
    'analyze_elf_sections',
    'analyze_elf_segments',
    'analyze_elf_symbols',
    'get_elf_packer_analysis',
    'get_elf_hardening_analysis',
    # Office analysis
    'get_comprehensive_office_analysis',
    'get_office_macro_analysis',
    'get_office_url_analysis'
]
