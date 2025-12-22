import subprocess
import os
import re
import sys
from pathlib import Path

class PDFObfuscationAnalyzer:
    """Analyzes PDF files for obfuscation and malicious indicators using pdfid"""
    
    def __init__(self):
        # Get the directory where this script is located
        self.utils_dir = Path(__file__).parent
        self.pdfid_path = self.utils_dir / "pdfid.py"
        
        # High-risk indicators
        self.high_risk_keys = [
            '/JS', '/JavaScript', '/OpenAction', '/AA', '/Launch',
            '/EmbeddedFile', '/RichMedia', '/XFA', '/AcroForm', '/JBIG2Decode'
        ]
        
        # Low-risk filters (normal compression)
        self.normal_filters = ['FlateDecode', 'DCTDecode', 'JPXDecode']
        
        # Suspicious filters (potential obfuscation)
        self.suspicious_filters = [
            'ASCIIHexDecode', 'ASCII85Decode', 'LZWDecode', 
            'RunLengthDecode', 'JBIG2Decode'
        ]
    
    def analyze(self, pdf_path):
        """Run pdfid.py and analyze the results"""
        try:
            if not os.path.exists(pdf_path):
                return {'error': 'PDF file not found'}
            
            if not os.path.exists(self.pdfid_path):
                return {'error': 'pdfid.py not found in utils directory'}
            
            # Run pdfid.py
            result = subprocess.run(
                [sys.executable, str(self.pdfid_path), pdf_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return {'error': f'pdfid.py failed: {result.stderr}'}
            
            # Parse the output
            parsed_data = self._parse_pdfid_output(result.stdout)
            
            # Analyze for obfuscation and malicious indicators
            analysis = self._analyze_indicators(parsed_data)
            
            return {
                'raw_data': parsed_data,
                'analysis': analysis,
                'risk_score': analysis['risk_score'],
                'risk_level': analysis['risk_level'],
                'indicators': analysis['indicators'],
                'recommendations': analysis['recommendations']
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Analysis timeout - PDF may be corrupted or too large'}
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    def _parse_pdfid_output(self, output):
        """Parse pdfid.py output into structured data"""
        data = {
            'header': '',
            'counts': {},
            'raw_output': output
        }
        
        lines = output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract PDF header
            if 'PDF Header:' in line:
                data['header'] = line.split('PDF Header:')[1].strip()
                continue
            
            # Extract counts (e.g., "obj                   10")
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0]
                try:
                    value = int(parts[-1])
                    data['counts'][key] = value
                except ValueError:
                    continue
        
        return data
    
    def _analyze_indicators(self, parsed_data):
        """Analyze parsed data for malicious indicators and obfuscation"""
        counts = parsed_data.get('counts', {})
        
        indicators = {
            'high_risk_features': [],
            'structural_anomalies': [],
            'obfuscation_techniques': [],
            'suspicious_characteristics': []
        }
        
        risk_score = 0
        
        # Check high-risk features
        for key in self.high_risk_keys:
            if counts.get(key, 0) > 0:
                indicators['high_risk_features'].append({
                    'feature': key,
                    'count': counts[key],
                    'description': self._get_feature_description(key)
                })
                risk_score += self._get_feature_risk_weight(key)
        
        # Check for encryption
        if counts.get('/Encrypt', 0) > 0:
            indicators['high_risk_features'].append({
                'feature': '/Encrypt',
                'count': counts['/Encrypt'],
                'description': 'Encrypted PDF - may hide payloads or evade inspection'
            })
            risk_score += 15
        
        # Check structural anomalies
        obj_count = counts.get('obj', 0)
        endobj_count = counts.get('endobj', 0)
        stream_count = counts.get('stream', 0)
        endstream_count = counts.get('endstream', 0)
        
        # Object/endobj mismatch
        if obj_count != endobj_count:
            indicators['structural_anomalies'].append({
                'anomaly': 'Object count mismatch',
                'details': f'obj={obj_count}, endobj={endobj_count}',
                'risk': 'Malformed PDF structure, possible tampering'
            })
            risk_score += 10
        
        # Stream/endstream mismatch
        if stream_count != endstream_count:
            indicators['structural_anomalies'].append({
                'anomaly': 'Stream count mismatch',
                'details': f'stream={stream_count}, endstream={endstream_count}',
                'risk': 'Corrupted or manipulated streams'
            })
            risk_score += 10
        
        # Check for object streams (can hide objects)
        if counts.get('/ObjStm', 0) > 0:
            indicators['obfuscation_techniques'].append({
                'technique': 'Object Streams',
                'count': counts['/ObjStm'],
                'description': 'Objects hidden inside streams - common obfuscation'
            })
            risk_score += 8
        
        # Check for suspicious PDF characteristics
        page_count = counts.get('/Page', 0)
        
        # Small PDF with multiple streams (suspicious)
        if page_count <= 2 and stream_count >= 3:
            indicators['suspicious_characteristics'].append({
                'characteristic': 'Small PDF with multiple streams',
                'details': f'{page_count} page(s), {stream_count} streams',
                'concern': 'May contain embedded shellcode or hidden payloads'
            })
            risk_score += 12
        
        # Multiple xref tables (unusual)
        xref_count = counts.get('xref', 0)
        if xref_count > 2:
            indicators['suspicious_characteristics'].append({
                'characteristic': 'Multiple cross-reference tables',
                'details': f'{xref_count} xref tables',
                'concern': 'Possible tampering or incremental updates hiding malicious content'
            })
            risk_score += 7
        
        # No pages (unusual for legitimate PDFs)
        if page_count == 0 and obj_count > 0:
            indicators['suspicious_characteristics'].append({
                'characteristic': 'PDF with no pages',
                'details': 'Zero pages but has objects',
                'concern': 'Not a normal document - may be exploit container'
            })
            risk_score += 20
        
        # Determine risk level
        risk_level = self._calculate_risk_level(risk_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(indicators, counts)
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'indicators': indicators,
            'recommendations': recommendations,
            'summary': self._generate_summary(indicators, risk_level)
        }
    
    def _get_feature_description(self, feature):
        """Get description for high-risk feature"""
        descriptions = {
            '/JS': 'JavaScript code - common code execution vector',
            '/JavaScript': 'JavaScript code - common code execution vector',
            '/OpenAction': 'Automatic action on document open - can trigger code',
            '/AA': 'Additional actions - can trigger code automatically',
            '/Launch': 'Launch external programs - high security risk',
            '/EmbeddedFile': 'Embedded files - may contain secondary payloads',
            '/RichMedia': 'Rich media content - container for payloads',
            '/XFA': 'XML Forms Architecture - often abused for hidden scripts',
            '/AcroForm': 'Acrobat forms - can hide scripts or payloads',
            '/JBIG2Decode': 'JBIG2 compression - used in known exploits (CVE-2021-30860)'
        }
        return descriptions.get(feature, 'Unknown high-risk feature')
    
    def _get_feature_risk_weight(self, feature):
        """Get risk weight for feature"""
        weights = {
            '/JS': 25,
            '/JavaScript': 25,
            '/OpenAction': 20,
            '/AA': 20,
            '/Launch': 30,
            '/EmbeddedFile': 15,
            '/RichMedia': 15,
            '/XFA': 12,
            '/AcroForm': 10,
            '/JBIG2Decode': 35  # Very high due to known exploits
        }
        return weights.get(feature, 10)
    
    def _calculate_risk_level(self, score):
        """Calculate risk level from score"""
        if score >= 60:
            return 'CRITICAL'
        elif score >= 40:
            return 'HIGH'
        elif score >= 20:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        else:
            return 'CLEAN'
    
    def _generate_recommendations(self, indicators, counts):
        """Generate actionable recommendations"""
        recommendations = []
        
        high_risk = indicators['high_risk_features']
        
        if any('/JS' in f['feature'] or '/JavaScript' in f['feature'] for f in high_risk):
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Extract and analyze JavaScript',
                'details': 'Use pdf-parser.py or peepdf to extract JS code for manual review'
            })
        
        if any('/Launch' in f['feature'] for f in high_risk):
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Sandbox execution required',
                'details': 'PDF attempts to launch external programs - analyze in isolated environment'
            })
        
        if any('/EmbeddedFile' in f['feature'] for f in high_risk):
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Extract embedded files',
                'details': 'Extract and scan all embedded files separately'
            })
        
        if counts.get('stream', 0) > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Decompress and analyze streams',
                'details': f'Analyze {counts["stream"]} stream(s) for hidden content, entropy, and shellcode patterns'
            })
        
        if indicators['obfuscation_techniques']:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Run YARA rules',
                'details': 'Scan decompressed streams with PDF exploit YARA rules'
            })
        
        if indicators['structural_anomalies']:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Manual structure analysis',
                'details': 'PDF structure anomalies detected - requires expert review'
            })
        
        # Always recommend entropy analysis
        recommendations.append({
            'priority': 'LOW',
            'action': 'Entropy analysis',
            'details': 'Calculate entropy of streams to detect encrypted/packed content'
        })
        
        return recommendations
    
    def _generate_summary(self, indicators, risk_level):
        """Generate human-readable summary"""
        total_indicators = (
            len(indicators['high_risk_features']) +
            len(indicators['structural_anomalies']) +
            len(indicators['obfuscation_techniques']) +
            len(indicators['suspicious_characteristics'])
        )
        
        if total_indicators == 0:
            return 'PDF appears clean with no suspicious indicators detected.'
        
        summary_parts = []
        
        if indicators['high_risk_features']:
            features = ', '.join([f['feature'] for f in indicators['high_risk_features']])
            summary_parts.append(f'High-risk features: {features}')
        
        if indicators['structural_anomalies']:
            summary_parts.append(f'{len(indicators["structural_anomalies"])} structural anomaly(ies) detected')
        
        if indicators['obfuscation_techniques']:
            summary_parts.append(f'{len(indicators["obfuscation_techniques"])} obfuscation technique(s) found')
        
        if indicators['suspicious_characteristics']:
            summary_parts.append(f'{len(indicators["suspicious_characteristics"])} suspicious characteristic(s) identified')
        
        return f'{risk_level} risk. ' + '; '.join(summary_parts) + '.'
