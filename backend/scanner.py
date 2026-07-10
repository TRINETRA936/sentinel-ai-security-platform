import requests
import time
import hashlib
import os
from typing import Dict, Optional, Any

class VirusTotalScanner:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        } if api_key else {}
        self.use_mock = not api_key
        
        if self.use_mock:
            print("🔧 Running in DEMO mode - using mock scan data")
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan a file using VirusTotal API or mock data"""
        
        if self.use_mock:
            return self._mock_scan(file_path)
        
        try:
            # Upload file for scanning
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=self.headers,
                    files=files,
                    timeout=30
                )
            
            if response.status_code != 200:
                return {'error': f'Upload failed: {response.text}'}
            
            data = response.json()
            analysis_id = data.get('data', {}).get('id')
            
            if not analysis_id:
                return {'error': 'No analysis ID returned'}
            
            # Wait for analysis to complete
            time.sleep(15)
            
            # Get analysis results
            analysis_url = f"{self.base_url}/analyses/{analysis_id}"
            response = requests.get(analysis_url, headers=self.headers, timeout=30)
            
            if response.status_code != 200:
                return {'error': f'Analysis failed: {response.text}'}
            
            result = response.json()
            
            # Parse results
            attributes = result.get('data', {}).get('attributes', {})
            stats = attributes.get('stats', {})
            
            # Get file details
            file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            file_info = self.get_file_info(file_hash)
            
            return {
                'success': True,
                'filename': os.path.basename(file_path),
                'hash': file_hash,
                'scan_date': attributes.get('date'),
                'stats': stats,
                'total_engines': sum(stats.values()),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'timeout': stats.get('timeout', 0),
                'confirmed_timeout': stats.get('confirmed-timeout', 0),
                'failure': stats.get('failure', 0),
                'type_unsupported': stats.get('type-unsupported', 0),
                'file_info': file_info,
                'detections': self.get_detections(file_hash)
            }
            
        except requests.exceptions.Timeout:
            return {'error': 'Request to VirusTotal timed out'}
        except requests.exceptions.ConnectionError:
            return {'error': 'Could not connect to VirusTotal API'}
        except Exception as e:
            return {'error': str(e)}
    
    def _mock_scan(self, file_path: str) -> Dict:
        """Generate mock scan data for testing"""
        file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
        filename = os.path.basename(file_path)
        
        # Check for EICAR test file first (by content)
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                content_str = content.decode('utf-8', errors='ignore')
                
                # Check for EICAR signature
                if 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in content_str or 'X5O!P%@AP[4\PZX54' in content_str:
                    # This is the EICAR test file
                    return {
                        'success': True,
                        'filename': filename,
                        'hash': file_hash,
                        'scan_date': int(time.time()),
                        'stats': {
                            'malicious': 58,
                            'suspicious': 0,
                            'undetected': 12,
                            'harmless': 0,
                            'timeout': 0,
                            'confirmed-timeout': 0,
                            'failure': 0,
                            'type-unsupported': 0
                        },
                        'total_engines': 70,
                        'malicious': 58,
                        'suspicious': 0,
                        'undetected': 12,
                        'harmless': 0,
                        'timeout': 0,
                        'confirmed_timeout': 0,
                        'failure': 0,
                        'type_unsupported': 0,
                        'file_info': {
                            'size': os.path.getsize(file_path),
                            'type': 'application/octet-stream',
                            'names': [filename],
                            'magic': 'EICAR test file',
                            'first_submission_date': int(time.time()) - 86400,
                            'last_submission_date': int(time.time()),
                            'last_analysis_date': int(time.time()),
                            'tags': ['eicar', 'test', 'antivirus-test']
                        },
                        'detections': {
                            'McAfee': {'detected': True, 'result': 'EICAR.test', 'category': 'malicious'},
                            'Symantec': {'detected': True, 'result': 'EICAR Test File', 'category': 'malicious'},
                            'Kaspersky': {'detected': True, 'result': 'EICAR-Test-File', 'category': 'malicious'},
                            'BitDefender': {'detected': True, 'result': 'EICAR.Test.File', 'category': 'malicious'},
                            'Avast': {'detected': True, 'result': 'Win32:EICAR', 'category': 'malicious'},
                            'Norton': {'detected': True, 'result': 'EICAR_Test_File', 'category': 'malicious'},
                            'ESET': {'detected': True, 'result': 'EICAR/Test', 'category': 'malicious'},
                            'F-Secure': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'TrendMicro': {'detected': True, 'result': 'EICAR.COM', 'category': 'malicious'},
                            'McAfee-GW': {'detected': True, 'result': 'Eicar.test', 'category': 'malicious'},
                            'AVG': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Panda': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'ClamAV': {'detected': True, 'result': 'Eicar-Test-Signature', 'category': 'malicious'},
                            'Sophos': {'detected': True, 'result': 'EICAR-AV-Test', 'category': 'malicious'},
                            'Microsoft': {'detected': True, 'result': 'Virus:EICAR', 'category': 'malicious'},
                            'Comodo': {'detected': True, 'result': 'EICAR-Test', 'category': 'malicious'},
                            'DrWeb': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Avira': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Bitdefender': {'detected': True, 'result': 'EICAR.Test', 'category': 'malicious'},
                            'GData': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Ikarus': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Jiangmin': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'K7GW': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Kingsoft': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'NANO': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Qihoo-360': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Rising': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Tencent': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Trustlook': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Webroot': {'detected': True, 'result': 'EICAR', 'category': 'malicious'},
                            'Zoner': {'detected': True, 'result': 'EICAR', 'category': 'malicious'}
                        }
                    }
                
                # Check for GTUBE (spam test) - should be safe
                if 'GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL' in content_str:
                    # GTUBE is for spam, not viruses - it should be safe
                    return {
                        'success': True,
                        'filename': filename,
                        'hash': file_hash,
                        'scan_date': int(time.time()),
                        'stats': {
                            'malicious': 0,
                            'suspicious': 0,
                            'undetected': 70,
                            'harmless': 70,
                            'timeout': 0,
                            'confirmed-timeout': 0,
                            'failure': 0,
                            'type-unsupported': 0
                        },
                        'total_engines': 70,
                        'malicious': 0,
                        'suspicious': 0,
                        'undetected': 70,
                        'harmless': 70,
                        'timeout': 0,
                        'confirmed_timeout': 0,
                        'failure': 0,
                        'type_unsupported': 0,
                        'file_info': {
                            'size': os.path.getsize(file_path),
                            'type': 'text/plain',
                            'names': [filename],
                            'magic': 'ASCII text',
                            'first_submission_date': int(time.time()) - 86400,
                            'last_submission_date': int(time.time()),
                            'last_analysis_date': int(time.time()),
                            'tags': ['clean', 'safe', 'spam-test']
                        },
                        'detections': {}
                    }
        except:
            pass
        
        # Determine mock result based on file extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        
        # Create different mock results for different file types
        if ext in ['exe', 'dll', 'scr', 'com', 'bat', 'bin']:
            malicious = 15
            suspicious = 5
            total_engines = 70
            detections = {
                'McAfee': {'detected': True, 'result': 'Trojan.Generic', 'category': 'malicious'},
                'Symantec': {'detected': True, 'result': 'Malware.Agent', 'category': 'malicious'},
                'Kaspersky': {'detected': True, 'result': 'HEUR:Trojan.Win32.Generic', 'category': 'malicious'},
                'BitDefender': {'detected': True, 'result': 'Trojan.GenericKD.123456', 'category': 'malicious'},
                'Avast': {'detected': True, 'result': 'Win32:Malware-gen', 'category': 'malicious'},
                'Norton': {'detected': True, 'result': 'Trojan.Gen', 'category': 'malicious'},
                'ESET': {'detected': True, 'result': 'Win32/TrojanDownloader', 'category': 'malicious'},
                'F-Secure': {'detected': True, 'result': 'Trojan:W32/Generic', 'category': 'malicious'},
                'TrendMicro': {'detected': True, 'result': 'TROJ_GEN.R002C0PLJ21', 'category': 'malicious'},
                'McAfee-GW': {'detected': True, 'result': 'Trojan.Generic.1', 'category': 'malicious'},
                'AVG': {'detected': True, 'result': 'Win32:Malware-gen', 'category': 'malicious'},
                'Panda': {'detected': True, 'result': 'Trj/CI.A', 'category': 'malicious'},
                'ClamAV': {'detected': True, 'result': 'Win.Trojan.Generic-12345', 'category': 'malicious'}
            }
        elif ext in ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']:
            malicious = 3
            suspicious = 2
            total_engines = 65
            detections = {
                'McAfee': {'detected': True, 'result': 'W97M.Downloader', 'category': 'malicious'},
                'Symantec': {'detected': True, 'result': 'Trojan.Mdropper', 'category': 'malicious'},
                'Kaspersky': {'detected': True, 'result': 'HEUR:Trojan.Script.Generic', 'category': 'malicious'}
            }
        elif ext in ['zip', 'rar', '7z', 'gz', 'tar']:
            malicious = 5
            suspicious = 3
            total_engines = 68
            detections = {
                'Kaspersky': {'detected': True, 'result': 'HEUR:Trojan.Win32.Generic', 'category': 'malicious'},
                'BitDefender': {'detected': True, 'result': 'Gen:Variant.Johnnie.1', 'category': 'malicious'},
                'Avast': {'detected': True, 'result': 'Win32:Malware-gen', 'category': 'malicious'}
            }
        elif ext in ['js', 'vbs', 'ps1', 'py']:
            malicious = 4
            suspicious = 1
            total_engines = 60
            detections = {
                'Kaspersky': {'detected': True, 'result': 'HEUR:Trojan.Script.Generic', 'category': 'malicious'},
                'McAfee': {'detected': True, 'result': 'Script.Trojan', 'category': 'malicious'}
            }
        else:
            malicious = 0
            suspicious = 0
            total_engines = 60
            detections = {}
        
        return {
            'success': True,
            'filename': filename,
            'hash': file_hash,
            'scan_date': int(time.time()),
            'stats': {
                'malicious': malicious,
                'suspicious': suspicious,
                'undetected': total_engines - malicious - suspicious,
                'harmless': 0,
                'timeout': 0,
                'confirmed-timeout': 0,
                'failure': 0,
                'type-unsupported': 0
            },
            'total_engines': total_engines,
            'malicious': malicious,
            'suspicious': suspicious,
            'undetected': total_engines - malicious - suspicious,
            'harmless': 0,
            'timeout': 0,
            'confirmed_timeout': 0,
            'failure': 0,
            'type_unsupported': 0,
            'file_info': {
                'size': os.path.getsize(file_path),
                'type': f'application/x-{ext}' if ext else 'application/octet-stream',
                'names': [filename],
                'magic': f'{ext.upper()} file' if ext else 'Unknown file',
                'first_submission_date': int(time.time()) - 86400,
                'last_submission_date': int(time.time()),
                'last_analysis_date': int(time.time()),
                'tags': ['malware', 'trojan', 'suspicious'] if malicious > 0 else ['clean', 'safe']
            },
            'detections': detections
        }
    
    def get_file_info(self, file_hash: str) -> Dict:
        """Get file information from VirusTotal"""
        if self.use_mock:
            return {}
        
        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                return {
                    'size': attributes.get('size'),
                    'type': attributes.get('type_description'),
                    'names': attributes.get('names', []),
                    'magic': attributes.get('magic'),
                    'first_submission_date': attributes.get('first_submission_date'),
                    'last_submission_date': attributes.get('last_submission_date'),
                    'last_analysis_date': attributes.get('last_analysis_date'),
                    'tags': attributes.get('tags', [])
                }
            return {}
        except:
            return {}
    
    def get_detections(self, file_hash: str) -> Dict:
        """Get detailed detection information"""
        if self.use_mock:
            return {}
        
        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                results = attributes.get('last_analysis_results', {})
                
                detections = {}
                for engine, result in results.items():
                    detections[engine] = {
                        'detected': result.get('category') == 'malicious',
                        'result': result.get('result'),
                        'category': result.get('category')
                    }
                return detections
            return {}
        except:
            return {}