"""
Example: Using the CVSS-based Unified Analyzer

This example demonstrates how to use the new unified analysis system
with standardized CVSS risk scoring.
"""

import sys
import json
from pathlib import Path

# Add backend utils to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.unified_analyzer import analyze_file_with_cvss


def main():
    """
    Example of analyzing a file with CVSS-based risk scoring
    """
    
    if len(sys.argv) < 2:
        print("Usage: python example_cvss_analysis.py <file_path>")
        print("\nThis will analyze the file and provide a standardized CVSS risk score")
        print("instead of multiple individual risk scores.")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    print("=" * 80)
    print("CVSS-Based Malware Analysis")
    print("=" * 80)
    print(f"\nAnalyzing: {file_path}")
    print("-" * 80)
    
    # Perform unified analysis with CVSS scoring
    result = analyze_file_with_cvss(file_path)
    
    if not result['success']:
        print(f"\nError: {result.get('error', 'Unknown error')}")
        sys.exit(1)
    
    # Display key results
    print(f"\nFile Information:")
    print(f"  Filename: {result['filename']}")
    print(f"  File Size: {result['file_size']:,} bytes")
    print(f"  File Type: {result['file_type']}")
    print(f"\nCryptographic Hashes:")
    print(f"  MD5:    {result['hashes']['md5']}")
    print(f"  SHA256: {result['hashes']['sha256']}")
    
    # Display CVSS Risk Score (THE MAIN RESULT)
    print("\n" + "=" * 80)
    print("CVSS RISK ASSESSMENT")
    print("=" * 80)
    print(f"\nCVSS Score:    {result['cvss_score']}/10.0")
    print(f"Severity:      {result['severity']}")
    print(f"Threat Level:  {result['threat_level']}")
    print(f"Verdict:       {result['verdict']}")
    print(f"\n{result['recommendation']}")
    
    # Display contributing factors
    if result['analysis'].get('contributing_factors'):
        print("\nThreat Indicators Contributing to Score:")
        print("-" * 80)
        for i, factor in enumerate(result['analysis']['contributing_factors'][:5], 1):
            indicator = factor['indicator'].replace('_', ' ').title()
            count = factor['count']
            contribution = factor['contribution']
            print(f"  {i}. {indicator}")
            print(f"     Count: {count} | Impact: +{contribution} points")
    
    # Severity level explanation
    print("\n" + "=" * 80)
    print("CVSS Severity Ratings (Based on Industry Standard):")
    print("=" * 80)
    print("  None:     0.0           - No threats detected")
    print("  Low:      0.1 - 3.9     - Minor suspicious characteristics")
    print("  Medium:   4.0 - 6.9     - Suspicious behavior detected")
    print("  High:     7.0 - 8.9     - Dangerous capabilities found")
    print("  Critical: 9.0 - 10.0    - Highly likely malicious")
    
    # Optional: Save full results to JSON
    output_file = f"{file_path}_cvss_analysis.json"
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\nFull analysis saved to: {output_file}")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
