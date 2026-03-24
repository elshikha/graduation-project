"""
Demonstration: Old vs New Risk Scoring System
Shows the improvement from multiple confusing scores to single CVSS score
"""

print("=" * 80)
print("COMPARISON: OLD vs NEW RISK SCORING SYSTEM")
print("=" * 80)
print()

# Simulate OLD system output (CONFUSING!)
print("❌ OLD SYSTEM - Multiple Confusing Scores:")
print("-" * 80)
print("""
📊 PDF Structure Analysis
   Risk Score: 8
   Risk Level: HIGH

📊 YARA Scan Results  
   Total Score: 3
   Rule Count: 2

📊 peepdf Analysis
   Risk Score: 4
   Suspicious Elements: 2

📊 Metadata Analysis
   Risk Score: 2
   
❓ TOTAL: 17 points??? What does this mean?
❓ Which score should I trust?
❓ Is this file dangerous or not?
""")

print()
print("=" * 80)
print()

# Simulate NEW system output (CLEAR!)
print("✅ NEW SYSTEM - Single CVSS Score:")
print("-" * 80)

from backend.utils.cvss_calculator import CVSSCalculator

# Same threat data, but now processed through CVSS
pdf_threats = {
    'code_execution': 2,        # JavaScript + AutoAction
    'system_modification': 1,    # Launch action
    'embedded_payload': 1,       # Embedded files
    'encryption': 1,             # High entropy
}

result = CVSSCalculator.calculate_cvss_score(pdf_threats)

print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    CVSS RISK ASSESSMENT                      ║
╚══════════════════════════════════════════════════════════════╝

   CVSS Score:      {result['cvss_score']}/10.0
   Severity:        {result['severity']}
   Threat Level:    {result['threat_level']}
   
   Verdict:         File demonstrates dangerous capabilities
   
   Recommendation:  {CVSSCalculator.get_recommendation(result)}

   Contributing Threat Indicators:
""")

for i, factor in enumerate(result['contributing_factors'], 1):
    indicator = factor['indicator'].replace('_', ' ').title()
    print(f"   {i}. {indicator:30} +{factor['contribution']:4.1f} points")

print()
print("=" * 80)
print()

# Show the scale
print("📊 CVSS SEVERITY SCALE (Industry Standard)")
print("-" * 80)
print("""
   0.0         │ None     │ ✅ Safe - No action needed
   0.1 - 3.9   │ Low      │ ⚠️  Proceed with caution
   4.0 - 6.9   │ Medium   │ 🔶 Sandboxed analysis recommended
   7.0 - 8.9   │ High     │ 🔴 Do NOT execute without containment
   9.0 - 10.0  │ Critical │ ⛔ QUARANTINE immediately
""")

print("=" * 80)
print()
print("✅ BENEFITS OF NEW SYSTEM:")
print("-" * 80)
print("""
   • ONE clear, standardized risk score (0-10)
   • Based on industry-standard CVSS methodology
   • Consistent across ALL file types (PDF, EXE, etc.)
   • Transparent - shows what contributes to the score
   • Actionable - provides clear security recommendations
   • No more confusion with multiple competing scores!
""")
print("=" * 80)
