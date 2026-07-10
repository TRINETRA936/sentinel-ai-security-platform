import json
from typing import Dict, Any
from datetime import datetime

class ThreatAnalyzer:
    def __init__(self):
        self.threat_levels = {
            'safe': {'min': 0, 'max': 20},
            'low': {'min': 21, 'max': 40},
            'medium': {'min': 41, 'max': 60},
            'high': {'min': 61, 'max': 80},
            'critical': {'min': 81, 'max': 100}
        }
        
        self.malware_families = {
            'Trojan': ['trojan', 'troj'],
            'Ransomware': ['ransom', 'locker', 'crypt'],
            'Worm': ['worm'],
            'Spyware': ['spy', 'keylogger'],
            'Adware': ['adware', 'ad'],
            'Rootkit': ['rootkit'],
            'Backdoor': ['backdoor', 'back'],
            'Botnet': ['bot', 'zombie'],
            'EICAR': ['eicar', 'test']
        }
    
    def analyze(self, scan_result: Dict, file_hash: str) -> Dict:
        """Analyze scan results and determine threat level"""
        
        # Check if scan had errors
        if 'error' in scan_result:
            return {
                'error': scan_result['error'],
                'status': 'Error',
                'risk_score': 0,
                'threat_level': 'Unknown'
            }
        
        # Get detection statistics with safe defaults
        malicious = scan_result.get('malicious', 0)
        suspicious = scan_result.get('suspicious', 0)
        total = scan_result.get('total_engines', 0)
        
        # Handle division by zero
        if total == 0:
            # If no engines, check if it's a known test file
            filename = scan_result.get('filename', '').lower()
            if 'eicar' in filename:
                # EICAR test file - give it a moderate risk score
                risk_score = 45
                malware_family = 'EICAR Test'
                threat_level = 'Medium'
                status = 'Medium Risk'
            else:
                risk_score = 0
                malware_family = 'Unknown'
                threat_level = 'Safe'
                status = 'Safe'
            
            return {
                'file_hash': file_hash,
                'risk_score': risk_score,
                'threat_level': threat_level,
                'status': status,
                'malware_family': malware_family,
                'detections': {},
                'statistics': {
                    'malicious': 0,
                    'suspicious': 0,
                    'undetected': 0,
                    'harmless': 0
                },
                'file_info': scan_result.get('file_info', {}),
                'scan_date': datetime.now().isoformat(),
                'recommendations': self.generate_recommendations(risk_score, malware_family)
            }
        
        # Calculate base score from detections
        detection_score = (malicious * 100 + suspicious * 50) / total
        
        # Additional factors (can be expanded)
        file_info = scan_result.get('file_info', {})
        
        # Check for suspicious file names
        name_score = 0
        names = file_info.get('names', [])
        for name in names:
            if any(indicator in name.lower() for indicator in ['payload', 'exploit', 'malware']):
                name_score += 20
        
        # Check file type
        type_score = 0
        file_type = file_info.get('type', '').lower()
        suspicious_types = ['pe32', 'executable', 'script', 'macro']
        if any(t in file_type for t in suspicious_types):
            type_score += 10
        
        # Calculate final risk score
        risk_score = min(100, int(detection_score + name_score + type_score))
        
        # Determine threat level
        threat_level = self.get_threat_level(risk_score)
        
        # Determine malware family
        malware_family = self.identify_malware_family(scan_result.get('detections', {}))
        
        # Check for EICAR test file
        if not malware_family or malware_family == 'Unknown':
            filename = scan_result.get('filename', '').lower()
            if 'eicar' in filename:
                malware_family = 'EICAR Test'
                risk_score = max(risk_score, 45)  # Ensure at least medium risk
        
        # Determine status
        status = 'Safe' if risk_score < 20 else 'High Risk' if risk_score >= 60 else 'Medium Risk'
        
        return {
            'file_hash': file_hash,
            'risk_score': risk_score,
            'threat_level': threat_level,
            'status': status,
            'malware_family': malware_family,
            'detections': scan_result.get('detections', {}),
            'statistics': {
                'malicious': malicious,
                'suspicious': suspicious,
                'undetected': scan_result.get('undetected', 0),
                'harmless': scan_result.get('harmless', 0)
            },
            'file_info': file_info,
            'scan_date': datetime.now().isoformat(),
            'recommendations': self.generate_recommendations(risk_score, malware_family)
        }
    
    def get_threat_level(self, risk_score: int) -> str:
        """Determine threat level based on risk score"""
        for level, thresholds in self.threat_levels.items():
            if thresholds['min'] <= risk_score <= thresholds['max']:
                return level.capitalize()
        return 'Unknown'
    
    def identify_malware_family(self, detections: Dict) -> str:
        """Identify malware family based on detection signatures"""
        family_scores = {}
        
        for engine, result in detections.items():
            if result.get('detected', False):
                detection_name = result.get('result', '').lower()
                
                for family, keywords in self.malware_families.items():
                    for keyword in keywords:
                        if keyword in detection_name:
                            family_scores[family] = family_scores.get(family, 0) + 1
        
        if family_scores:
            return max(family_scores, key=family_scores.get)
        return 'Unknown'
    
    def generate_recommendations(self, risk_score: int, malware_family: str) -> list:
        """Generate security recommendations based on threat analysis"""
        recommendations = []
        
        # Special case for EICAR test file
        if malware_family == 'EICAR Test':
            recommendations.append('This is the EICAR test file - used for testing antivirus software')
            recommendations.append('No action required - this is a safe test file')
            recommendations.append('Your antivirus software should detect this as a test virus')
            return recommendations
        
        if risk_score >= 80:
            recommendations.append('⚠️ CRITICAL: Immediately quarantine the file')
            recommendations.append('🔒 Isolate affected system from network')
            recommendations.append('🔄 Run full system antivirus scan')
            recommendations.append('🔍 Check for indicators of compromise')
            if malware_family == 'Ransomware':
                recommendations.append('💾 Disable file sharing and backups')
                recommendations.append('🔐 Check for encrypted files')
            elif malware_family == 'Trojan':
                recommendations.append('🌐 Check for unauthorized network connections')
                recommendations.append('👤 Review user account activities')
        
        elif risk_score >= 60:
            recommendations.append('⚠️ Quarantine the file')
            recommendations.append('🔍 Run targeted antivirus scan')
            recommendations.append('📊 Monitor system behavior')
            recommendations.append('🔄 Update antivirus definitions')
        
        elif risk_score >= 40:
            recommendations.append('📋 Monitor the file and its behavior')
            recommendations.append('🔄 Update security software')
            recommendations.append('📁 Review file origin and permissions')
        
        else:
            recommendations.append('✅ File appears safe, but maintain vigilance')
            recommendations.append('🔄 Keep security software updated')
        
        return recommendations