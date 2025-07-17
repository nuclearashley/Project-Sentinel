import hashlib
import requests
import os
import time
from typing import Dict, Optional, Tuple

class OSINTChecker:
    """
    OSINT (Open Source Intelligence) checker for known malicious file hashes
    """
    
    def __init__(self):
        # Mock database of known malicious hashes for demonstration
        # In production, this would integrate with VirusTotal, Hybrid Analysis, etc.
        self.malicious_hashes = {
            # Removed empty file hash to avoid false positives in testing
            # "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Known malware - Empty file hash",
            "d41d8cd98f00b204e9800998ecf8427e": "Known malware - MD5 empty file",
            "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f": "Known malware - Hello World",
            "5d41402abc4b2a76b9719d911017c592": "Known malware - Hello MD5",
            "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9": "Known malware - Hello SHA256",
            "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78": "Known malware - Test file",
            "cd2eb0837c9b4c962c22d2ff8b5441b7b45805887f051d39bf133b583baf6860": "Known malware - Suspicious PDF",
            "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "Known malware - Suspicious executable"
        }
        
        # VirusTotal API configuration
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '64c677585c0856c000004edf7292f93a6feb8c12a7062f2c400e9a51328d720d')
        self.virustotal_base_url = "https://www.virustotal.com/api/v3"
        self.virustotal_headers = {
            "accept": "application/json",
            "x-apikey": self.virustotal_api_key
        }
        
        # Rate limiting for VirusTotal API
        self.last_vt_request = 0
        self.vt_rate_limit_delay = 1.0  # 1 second between requests (free tier limit)
    
    def calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise Exception(f"Error calculating hash: {str(e)}")
    
    def _rate_limit_virustotal(self):
        """Implement rate limiting for VirusTotal API"""
        current_time = time.time()
        time_since_last = current_time - self.last_vt_request
        if time_since_last < self.vt_rate_limit_delay:
            sleep_time = self.vt_rate_limit_delay - time_since_last
            time.sleep(sleep_time)
        self.last_vt_request = time.time()
    
    def check_virustotal(self, file_hash: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Check hash against VirusTotal API
        Returns: (is_malicious, source_info, details)
        """
        if not self.virustotal_api_key:
            return False, None, None
        
        try:
            # Rate limiting
            self._rate_limit_virustotal()
            
            # Make API request
            url = f"{self.virustotal_base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.virustotal_headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                file_info = data.get('data', {}).get('attributes', {})
                
                # Get analysis stats
                last_analysis_stats = file_info.get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                suspicious_count = last_analysis_stats.get('suspicious', 0)
                total_engines = sum(last_analysis_stats.values())
                
                # Get detailed analysis results
                last_analysis_results = file_info.get('last_analysis_results', {})
                
                # Determine if malicious
                is_malicious = malicious_count > 0
                
                if is_malicious:
                    # Get names of engines that detected malware
                    malicious_engines = []
                    for engine_name, result in last_analysis_results.items():
                        if result.get('category') == 'malicious':
                            malicious_engines.append(engine_name)
                    
                    source_info = f"VirusTotal: {malicious_count} engines detected malware"
                    details = {
                        "source": "VirusTotal API",
                        "hash": file_hash,
                        "malicious_count": malicious_count,
                        "suspicious_count": suspicious_count,
                        "total_engines": total_engines,
                        "malicious_engines": malicious_engines[:5],  # Limit to first 5
                        "detection_ratio": f"{malicious_count}/{total_engines}",
                        "last_analysis_date": file_info.get('last_analysis_date'),
                        "reputation": file_info.get('reputation', 0)
                    }
                    
                    return True, source_info, details
                else:
                    # File is clean
                    details = {
                        "source": "VirusTotal API",
                        "hash": file_hash,
                        "malicious_count": 0,
                        "suspicious_count": suspicious_count,
                        "total_engines": total_engines,
                        "detection_ratio": f"0/{total_engines}",
                        "last_analysis_date": file_info.get('last_analysis_date'),
                        "reputation": file_info.get('reputation', 0)
                    }
                    
                    return False, "VirusTotal: No engines detected malware", details
            
            elif response.status_code == 404:
                # Hash not found in VirusTotal database
                return False, "VirusTotal: Hash not found in database", {
                    "source": "VirusTotal API",
                    "hash": file_hash,
                    "status": "not_found"
                }
            
            else:
                # API error
                print(f"VirusTotal API error: {response.status_code} - {response.text}")
                return False, None, None
                
        except requests.exceptions.Timeout:
            print("VirusTotal API timeout")
            return False, None, None
        except requests.exceptions.RequestException as e:
            print(f"VirusTotal API request error: {str(e)}")
            return False, None, None
        except Exception as e:
            print(f"VirusTotal API error: {str(e)}")
            return False, None, None
    
    def check_osint_databases(self, file_hash: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Check hash against OSINT databases (local + VirusTotal)
        Returns: (is_malicious, source_info, details)
        """
        try:
            # First, check local mock database
            if file_hash in self.malicious_hashes:
                return True, self.malicious_hashes[file_hash], {
                    "source": "Mock OSINT Database",
                    "hash": file_hash,
                    "detection_time": "2024-01-01",
                    "threat_type": "Known malware"
                }
            
            # If not found locally, check VirusTotal
            vt_is_malicious, vt_source_info, vt_details = self.check_virustotal(file_hash)
            
            if vt_is_malicious:
                return True, vt_source_info, vt_details
            elif vt_source_info:  # VT returned a result (clean or not found)
                return False, vt_source_info, vt_details
            else:
                # VT failed, return local-only result
                return False, None, None
            
        except Exception as e:
            # Log error but don't fail the entire analysis
            print(f"OSINT check error: {str(e)}")
            return False, None, None
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Perform OSINT analysis on a file
        Returns analysis results with threat score and confidence level
        """
        try:
            # Calculate file hash
            file_hash = self.calculate_hash(file_path)
            
            # Check OSINT databases
            is_malicious, source_info, details = self.check_osint_databases(file_hash)
            
            # For OSINT, we either have a definitive match or no match
            if is_malicious:
                threat_score = 1.0  # Definitive malicious
                confidence_level = 0.95  # Very high confidence in known hashes
                confidence_factors = ["Known malicious hash in OSINT database"]
                rationale = f"OSINT match found: {source_info}"
            else:
                threat_score = 0.0  # No known threats
                confidence_level = 0.8  # High confidence that it's not a known malicious file
                confidence_factors = ["No matches in OSINT databases"]
                rationale = "No matches found in OSINT databases"
            
            result = {
                "hash": file_hash,
                "is_malicious": is_malicious,
                "threat_score": threat_score,
                "confidence_level": confidence_level,
                "confidence_factors": confidence_factors,
                "source": "OSINT Database" if is_malicious else None,
                "rationale": rationale,
                "details": details
            }
            
            return result
            
        except Exception as e:
            return {
                "hash": None,
                "is_malicious": False,
                "threat_score": 0.0,
                "confidence_level": 0.1,  # Very low confidence due to analysis failure
                "confidence_factors": ["Hash calculation failed"],
                "source": "Error",
                "rationale": f"OSINT analysis failed: {str(e)}",
                "details": None
            } 