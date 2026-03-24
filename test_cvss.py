"""
Quick test of CVSS Calculator
Demonstrates the new unified risk scoring system
"""

from backend.utils.cvss_calculator import CVSSCalculator

print("=" * 80)
print("CVSS RISK SCORING SYSTEM - TEST")
print("=" * 80)
print()

# Test 1: Simulated PDF with JavaScript and Launch actions
print("Test 1: Malicious PDF with JavaScript and Launch Actions")
print("-" * 80)

pdf_threats = {
    'code_execution': 3,      # JavaScript + OpenAction + AutoAction
    'system_modification': 1,  # Launch action
    'embedded_payload': 2,     # Embedded files
    'encryption': 1,           # High entropy
    'network_communication': 1 # URIs found
}

result = CVSSCalculator.calculate_cvss_score(pdf_threats)

print(f"Threat Indicators: {pdf_threats}")
print(f"\n✓ CVSS Score:    {result['cvss_score']}/10.0")
print(f"✓ Severity:      {result['severity']}")
print(f"✓ Threat Level:  {result['threat_level']}")
print(f"\nContributing Factors:")
for factor in result['contributing_factors']:
    print(f"  • {factor['indicator'].replace('_', ' ').title()}: +{factor['contribution']} points (count: {factor['count']})")

print(f"\nRecommendation: {CVSSCalculator.get_recommendation(result)}")
print()

# Test 2: Suspicious PE with multiple capabilities
print("\n" + "=" * 80)
print("Test 2: Suspicious PE with Network Communication")
print("-" * 80)

pe_threats = {
    'process_injection': 2,
    'network_communication': 3,
    'persistence': 1,
    'anti_analysis': 1,
    'suspicious_imports': 1,
    'high_entropy': 2
}

result = CVSSCalculator.calculate_cvss_score(pe_threats)

print(f"Threat Indicators: {pe_threats}")
print(f"\n✓ CVSS Score:    {result['cvss_score']}/10.0")
print(f"✓ Severity:      {result['severity']}")
print(f"✓ Threat Level:  {result['threat_level']}")
print(f"\nContributing Factors:")
for factor in result['contributing_factors']:
    print(f"  • {factor['indicator'].replace('_', ' ').title()}: +{factor['contribution']} points (count: {factor['count']})")

print(f"\nRecommendation: {CVSSCalculator.get_recommendation(result)}")
print()

# Test 3: Clean file
print("\n" + "=" * 80)
print("Test 3: Clean File (No Threats)")
print("-" * 80)

clean_threats = {}

result = CVSSCalculator.calculate_cvss_score(clean_threats)

print(f"Threat Indicators: {clean_threats}")
print(f"\n✓ CVSS Score:    {result['cvss_score']}/10.0")
print(f"✓ Severity:      {result['severity']}")
print(f"✓ Threat Level:  {result['threat_level']}")
print(f"\nRecommendation: {CVSSCalculator.get_recommendation(result)}")
print()

# Test 4: Critical malware
print("\n" + "=" * 80)
print("Test 4: Critical Malware (Multiple Severe Threats)")
print("-" * 80)

critical_threats = {
    'remote_exploit': 2,
    'privilege_escalation': 2,
    'code_execution': 3,
    'data_exfiltration': 2,
    'process_injection': 2,
    'anti_analysis': 2,
    'persistence': 2,
    'packer_detected': 1
}

result = CVSSCalculator.calculate_cvss_score(critical_threats)

print(f"Threat Indicators: {critical_threats}")
print(f"\n✓ CVSS Score:    {result['cvss_score']}/10.0")
print(f"✓ Severity:      {result['severity']}")
print(f"✓ Threat Level:  {result['threat_level']}")
print(f"\nTop Contributing Factors:")
for factor in result['contributing_factors'][:5]:
    print(f"  • {factor['indicator'].replace('_', ' ').title()}: +{factor['contribution']} points (count: {factor['count']})")

print(f"\nRecommendation: {CVSSCalculator.get_recommendation(result)}")
print()

# Summary
print("\n" + "=" * 80)
print("CVSS SEVERITY SCALE")
print("=" * 80)
print("""
Score Range  | Severity | Threat Level  | Action Required
-------------|----------|---------------|----------------------------------
0.0          | None     | Safe          | No action needed
0.1 - 3.9    | Low      | Low Risk      | Proceed with caution
4.0 - 6.9    | Medium   | Suspicious    | Sandboxed analysis recommended
7.0 - 8.9    | High     | Dangerous     | Do NOT execute without containment
9.0 - 10.0   | Critical | Malicious     | QUARANTINE immediately
""")

print("=" * 80)
print("✅ All tests completed successfully!")
print("=" * 80)
