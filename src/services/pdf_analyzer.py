import re
import os
from typing import Dict, List, Any
from pdfminer.high_level import extract_text
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.pdfpage import PDFPage
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
import io

class PDFAnalyzer:
    """
    PDF file analyzer for malicious content detection
    """
    
    def __init__(self):
        # Suspicious JavaScript patterns commonly found in malicious PDFs
        self.javascript_patterns = [
            r'/JavaScript',
            r'/JS',
            r'/OpenAction',
            r'/AA',
            r'app\.launchURL',
            r'app\.openDoc',
            r'this\.print',
            r'this\.submitForm',
            r'util\.printf',
            r'app\.alert',
            r'app\.beep',
            r'app\.mailMsg',
            r'getURL',
            r'spell\.check',
            r'Collab\.collectEmailInfo'
        ]
        
        # Suspicious PDF object patterns
        self.suspicious_objects = [
            r'/EmbeddedFile',
            r'/Launch',
            r'/SubmitForm',
            r'/ImportData',
            r'/GoToR',
            r'/Sound',
            r'/Movie',
            r'/RichMedia',
            r'/Flash',
            r'/U3D'
        ]
        
        # Suspicious URL patterns
        self.url_patterns = [
            r'https?://[^\s<>"\']+',
            r'ftp://[^\s<>"\']+',
            r'javascript:[^\s<>"\']+',
            r'data:[^\s<>"\']+',
            r'vbscript:[^\s<>"\']+',
            r'file://[^\s<>"\']+',
            r'\\\\[^\s<>"\']+',  # UNC paths
        ]
        
        # Encoding patterns that might hide malicious content
        self.encoding_patterns = [
            r'%[0-9a-fA-F]{2}',  # URL encoding
            r'&#[0-9]+;',        # HTML entity encoding
            r'&#x[0-9a-fA-F]+;', # Hex HTML entity encoding
            r'\\u[0-9a-fA-F]{4}', # Unicode escape
            r'\\x[0-9a-fA-F]{2}', # Hex escape
        ]
    
    def extract_text_content(self, file_path: str) -> str:
        """Extract text content from PDF file"""
        try:
            text = extract_text(file_path)
            return text if text else ""
        except Exception as e:
            print(f"Text extraction error: {str(e)}")
            return ""
    
    def analyze_raw_content(self, file_path: str) -> Dict[str, Any]:
        """Analyze raw PDF content for suspicious patterns"""
        try:
            with open(file_path, 'rb') as f:
                raw_content = f.read().decode('utf-8', errors='ignore')
            
            # Count suspicious patterns
            js_matches = 0
            object_matches = 0
            url_matches = 0
            encoding_matches = 0
            
            found_patterns = []
            
            # Check for JavaScript patterns
            for pattern in self.javascript_patterns:
                matches = re.findall(pattern, raw_content, re.IGNORECASE)
                if matches:
                    js_matches += len(matches)
                    found_patterns.append(f"{pattern} ({len(matches)} times)")
            
            # Check for suspicious objects
            for pattern in self.suspicious_objects:
                matches = re.findall(pattern, raw_content, re.IGNORECASE)
                if matches:
                    object_matches += len(matches)
                    found_patterns.append(f"{pattern} ({len(matches)} times)")
            
            # Check for URLs
            for pattern in self.url_patterns:
                matches = re.findall(pattern, raw_content, re.IGNORECASE)
                if matches:
                    url_matches += len(matches)
                    # Don't add every URL to avoid spam, just note that URLs were found
                    if pattern not in [p.split(' ')[0] for p in found_patterns]:
                        found_patterns.append(f"URLs found ({len(matches)} instances)")
            
            # Check for encoding patterns
            for pattern in self.encoding_patterns:
                matches = re.findall(pattern, raw_content, re.IGNORECASE)
                if matches:
                    encoding_matches += len(matches)
            
            return {
                "javascript_patterns": js_matches,
                "suspicious_objects": object_matches,
                "url_patterns": url_matches,
                "encoding_patterns": encoding_matches,
                "found_patterns": found_patterns,
                "raw_content_length": len(raw_content)
            }
            
        except Exception as e:
            print(f"Raw content analysis error: {str(e)}")
            return {
                "javascript_patterns": 0,
                "suspicious_objects": 0,
                "url_patterns": 0,
                "encoding_patterns": 0,
                "found_patterns": [],
                "raw_content_length": 0
            }
    
    def count_pdf_objects(self, file_path: str) -> int:
        """Count the number of objects in the PDF"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
            
            # Count PDF objects (lines starting with object declarations)
            object_count = len(re.findall(r'\d+\s+\d+\s+obj', content))
            return object_count
        except Exception:
            return 0
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive PDF analysis
        Returns analysis results with threat score and confidence level
        """
        try:
            # Extract text content
            text_content = self.extract_text_content(file_path)
            text_length = len(text_content)
            
            # Analyze raw content for suspicious patterns
            raw_analysis = self.analyze_raw_content(file_path)
            
            # Count PDF objects
            object_count = self.count_pdf_objects(file_path)
            
            # Calculate threat score (0.0 = safe, 1.0 = malicious)
            threat_score = 0.0
            reasons = []
            
            # JavaScript patterns (high risk)
            if raw_analysis["javascript_patterns"] > 0:
                threat_score += 0.4
                reasons.append(f"JavaScript patterns found ({raw_analysis['javascript_patterns']} instances)")
            
            # Suspicious objects (medium risk)
            if raw_analysis["suspicious_objects"] > 0:
                threat_score += 0.3
                reasons.append(f"Suspicious PDF objects found ({raw_analysis['suspicious_objects']} instances)")
            
            # URL patterns (low-medium risk)
            if raw_analysis["url_patterns"] > 5:  # Only flag if many URLs
                threat_score += 0.2
                reasons.append(f"Multiple URLs found ({raw_analysis['url_patterns']} instances)")
            
            # Encoding patterns (low risk, but suspicious in large quantities)
            if raw_analysis["encoding_patterns"] > 20:
                threat_score += 0.1
                reasons.append(f"Excessive encoding patterns ({raw_analysis['encoding_patterns']} instances)")
            
            # Complex structure (very low risk)
            if object_count > 100:
                threat_score += 0.05
                reasons.append(f"Complex PDF structure ({object_count} objects)")
            
            # Cap the threat score at 1.0
            threat_score = min(threat_score, 1.0)
            
            # Calculate confidence level (how confident we are in our analysis)
            confidence_factors = []
            base_confidence = 0.75  # Base confidence for PDF documents
            
            # Increase confidence based on analysis completeness
            if raw_analysis["raw_content_length"] > 5000:
                base_confidence += 0.1
                confidence_factors.append("Complete PDF content analysis")
            
            if text_length > 200:
                base_confidence += 0.1
                confidence_factors.append("Text content extracted successfully")
            
            if object_count > 0:
                base_confidence += 0.05
                confidence_factors.append("PDF structure analyzed")
            
            # Higher confidence if clear indicators found
            if raw_analysis["javascript_patterns"] > 0 or raw_analysis["suspicious_objects"] > 0:
                base_confidence += 0.1
                confidence_factors.append("Strong malicious indicators detected")
            
            # Lower confidence for edge cases
            if raw_analysis["raw_content_length"] < 1000:
                base_confidence -= 0.1
                confidence_factors.append("Limited content available for analysis")
            
            if text_length == 0:
                base_confidence -= 0.1
                confidence_factors.append("No text content extracted")
            
            confidence_level = min(base_confidence, 1.0)
            
            # Generate rationale
            is_malicious = threat_score > 0.5
            if threat_score > 0:
                rationale = f"PDF analysis completed. Threat score: {threat_score:.2f}. " + "; ".join(reasons)
            else:
                rationale = "PDF analysis completed. No suspicious indicators found"
            
            # Create features dictionary
            features = {
                "object_count": object_count,
                "suspicious_patterns": raw_analysis["javascript_patterns"] + raw_analysis["suspicious_objects"],
                "text_length": text_length,
                "found_patterns": raw_analysis["found_patterns"]
            }
            
            return {
                "is_malicious": is_malicious,
                "threat_score": threat_score,
                "confidence_level": confidence_level,
                "confidence_factors": confidence_factors,
                "rationale": rationale,
                "features": features,
                "source": "AI Analysis"
            }
            
        except Exception as e:
            return {
                "is_malicious": False,
                "threat_score": 0.0,
                "confidence_level": 0.3,  # Low confidence due to analysis failure
                "confidence_factors": ["Analysis failed"],
                "rationale": f"PDF analysis failed: {str(e)}",
                "features": {},
                "source": "Error"
            } 