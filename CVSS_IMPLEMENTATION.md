# CVSS-Based Risk Scoring Implementation

## Overview

The malware analysis program has been updated to use a **single, standardized CVSS (Common Vulnerability Scoring System) risk score** instead of multiple individual risk scores for each analysis card.

## Key Changes

### 1. **Unified CVSS Calculator** (`utils/cvss_calculator.py`)
- Implements CVSS v3.1 methodology for risk assessment
- Provides standardized 0-10 scoring scale
- Maps scores to industry-standard severity levels:
  - **None**: 0.0
  - **Low**: 0.1 - 3.9
  - **Medium**: 4.0 - 6.9
  - **High**: 7.0 - 8.9
  - **Critical**: 9.0 - 10.0

### 2. **Threat Indicators**
The CVSS calculator evaluates multiple threat indicators with weighted scoring:

#### Critical Threats (3.0 points each):
- Code execution capabilities
- Privilege escalation
- Remote exploit potential
- System modification

#### High Threats (2.0 points each):
- Data exfiltration
- Network communication
- Process injection
- Anti-analysis techniques
- Persistence mechanisms

#### Medium Threats (1.0-1.5 points each):
- Packer detected
- Suspicious imports
- Embedded payloads
- Obfuscation
- Encryption

#### Low Threats (0.3-0.7 points each):
- Anomalous structure
- Suspicious strings
- Unsigned binary
- High entropy

### 3. **Updated Analyzers**

#### PDF Analyzer (`utils/pdf_analyzer.py`)
- Removed internal risk_score calculations
- Uses `CVSSCalculator.calculate_pdf_score()` for unified scoring
- Evaluates: JavaScript, Launch actions, embedded files, entropy, YARA matches

#### PE Analyzer (via `utils/unified_analyzer.py`)
- Uses `CVSSCalculator.calculate_pe_score()` for unified scoring
- Integrates CAPA capabilities, DIE detections, PE structure analysis
- Maps detected capabilities to threat indicators

#### Unified Analyzer (`utils/unified_analyzer.py`)
- Single entry point: `analyze_file_with_cvss(file_path)`
- Automatically detects file type and applies appropriate analysis
- Returns consistent result structure with CVSS scoring

## Usage Example

```python
from utils.unified_analyzer import analyze_file_with_cvss

# Analyze any file type
result = analyze_file_with_cvss('suspicious_file.pdf')

# Access the single CVSS risk score
print(f"CVSS Score: {result['cvss_score']}/10.0")
print(f"Severity: {result['severity']}")
print(f"Threat Level: {result['threat_level']}")
print(f"Verdict: {result['verdict']}")
print(f"Recommendation: {result['recommendation']}")

# View contributing factors
for factor in result['analysis']['contributing_factors']:
    print(f"- {factor['indicator']}: +{factor['contribution']} points")
```

## Result Structure

```json
{
  "success": true,
  "filename": "sample.pdf",
  "file_size": 125840,
  "file_type": "PDF",
  "cvss_score": 7.5,
  "severity": "High",
  "threat_level": "Dangerous",
  "verdict": "DANGEROUS - Further analysis recommended",
  "recommendation": "File demonstrates dangerous capabilities...",
  "hashes": {
    "md5": "...",
    "sha256": "..."
  },
  "analysis": {
    "contributing_factors": [
      {
        "indicator": "code_execution",
        "count": 2,
        "contribution": 3.0
      },
      {
        "indicator": "network_communication",
        "count": 1,
        "contribution": 2.0
      }
    ],
    "structure": {...},
    "yara": {...},
    "peepdf": {...}
  }
}
```

## Benefits

1. **Standardized**: Uses industry-standard CVSS methodology
2. **Consistent**: Same scoring across all file types
3. **Transparent**: Shows which threat indicators contribute to score
4. **Actionable**: Provides clear security recommendations
5. **Simple**: One overall score instead of multiple confusing scores

## Integration with Frontend

The frontend should be updated to:
1. Display the single `cvss_score` prominently (0-10 scale)
2. Show `severity` level with appropriate color coding
3. Display `verdict` and `recommendation` to users
4. Optionally show `contributing_factors` for transparency

## References

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [Understanding CVSS Scores](https://plextrac.com/concepts/common-vulnerability-scoring-system-cvss/)
- [CVSS Scoring Guide](https://www.redlings.com/en/guide/cvss-score)

## Testing

Run the example script to test the new CVSS scoring:

```bash
cd backend
python example_cvss_analysis.py <path_to_file>
```

This will display the CVSS score and all contributing factors.
