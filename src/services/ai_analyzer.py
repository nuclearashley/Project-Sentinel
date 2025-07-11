import os
import tempfile
from typing import Dict, Any, Optional
from .osint_checker import OSINTChecker
from .pdf_analyzer import PDFAnalyzer
from .office_analyzer import OfficeAnalyzer
from .pe_analyzer import PEAnalyzer

class AIAnalyzer:
    """
    Main AI analyzer that coordinates all analysis components
    """
    
    def __init__(self):
        self.osint_checker = OSINTChecker()
        self.pdf_analyzer = PDFAnalyzer()
        self.office_analyzer = OfficeAnalyzer()
        self.pe_analyzer = PEAnalyzer()
        
        # Supported file extensions
        self.supported_extensions = {
            '.pdf': self.pdf_analyzer,
            '.docx': self.office_analyzer,
            '.xlsx': self.office_analyzer,
            '.exe': self.pe_analyzer
        }
    
    def get_file_extension(self, filename: str) -> str:
        """Get file extension in lowercase"""
        return os.path.splitext(filename.lower())[1]
    
    def is_supported_file(self, filename: str) -> bool:
        """Check if file type is supported"""
        ext = self.get_file_extension(filename)
        return ext in self.supported_extensions
    
    def analyze_file(self, file_path: str, filename: str) -> Dict[str, Any]:
        """
        Perform comprehensive file analysis
        Returns complete analysis results
        """
        try:
            # Check if file type is supported
            if not self.is_supported_file(filename):
                return {
                    'success': False,
                    'error': f'Unsupported file type. Supported formats: {", ".join(self.supported_extensions.keys())}',
                    'filename': filename
                }
            
            # First, perform OSINT check
            osint_result = self.osint_checker.analyze_file(file_path)
            
            # If OSINT found a known malicious file, return immediately
            if osint_result['is_malicious']:
                return {
                    'success': True,
                    'filename': filename,
                    'hash': osint_result['hash'],
                    'is_malicious': True,
                    'threat_score': osint_result['threat_score'],
                    'confidence_level': osint_result['confidence_level'],
                    'confidence_factors': osint_result['confidence_factors'],
                    'confidence_category': self.get_confidence_category(osint_result['confidence_level']),
                    'source': 'OSINT Database',
                    'rationale': osint_result['rationale'],
                    'details': osint_result['details'],
                    'features': None
                }
            
            # If OSINT didn't find it, proceed with AI analysis
            ext = self.get_file_extension(filename)
            analyzer = self.supported_extensions[ext]
            
            # Perform file-specific analysis
            analysis_result = analyzer.analyze_file(file_path)
            
            # Combine OSINT and AI analysis results
            # Use AI threat score since OSINT was clean
            threat_score = analysis_result['threat_score']
            
            # Combine confidence levels - if OSINT was clean and AI has high confidence, overall confidence is high
            osint_confidence = osint_result['confidence_level']
            ai_confidence = analysis_result['confidence_level']
            
            # Weighted average of confidences (OSINT gets slightly more weight if available)
            combined_confidence = (osint_confidence * 0.3) + (ai_confidence * 0.7)
            
            # Combine confidence factors
            combined_factors = osint_result['confidence_factors'] + analysis_result['confidence_factors']
            
            # Create final result
            final_result = {
                'success': True,
                'filename': filename,
                'hash': osint_result['hash'],
                'is_malicious': analysis_result['is_malicious'],
                'threat_score': threat_score,
                'confidence_level': combined_confidence,
                'confidence_factors': combined_factors,
                'confidence_category': self.get_confidence_category(combined_confidence),
                'source': analysis_result['source'],
                'rationale': analysis_result['rationale'],
                'features': analysis_result['features'],
                'details': None
            }
            
            return final_result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Analysis failed: {str(e)}',
                'filename': filename
            }
    
    def analyze_uploaded_file(self, uploaded_file) -> Dict[str, Any]:
        """
        Analyze a file uploaded via Flask request
        """
        # Save uploaded file to temporary location
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
            uploaded_file.save(temp_path)
        
        try:
            # Get original filename
            filename = uploaded_file.filename
            
            # Perform analysis
            result = self.analyze_file(temp_path, filename)
            
            return result
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except Exception:
                pass
    
    def get_threat_level(self, threat_score: float, is_malicious: bool) -> str:
        """
        Get human-readable threat level based on threat score
        """
        if not is_malicious:
            return "🟢 SAFE"
        elif threat_score >= 0.8:
            return "🔴 HIGH THREAT"
        elif threat_score >= 0.6:
            return "🟡 MEDIUM THREAT"
        elif threat_score >= 0.4:
            return "🟠 LOW THREAT"
        else:
            return "🔵 SUSPICIOUS"
    
    def generate_summary_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate a human-readable summary report
        """
        if not analysis_results.get('success', False):
            return f"Analysis failed: {analysis_results.get('error', 'Unknown error')}"
        
        filename = analysis_results['filename']
        is_malicious = analysis_results['is_malicious']
        confidence = analysis_results['confidence_level'] # Changed from confidence_level to confidence
        source = analysis_results['source']
        rationale = analysis_results['rationale']
        
        threat_level = self.get_threat_level(confidence, is_malicious)
        
        summary = f"""
File Analysis Report
====================
File: {filename}
Threat Level: {threat_level}
Malicious: {'Yes' if is_malicious else 'No'}
Confidence: {confidence:.2f} ({confidence*100:.1f}%)
Analysis Source: {source}

Rationale:
{rationale}

Analysis completed successfully.
        """
        
        return summary.strip()
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the analysis engine
        """
        return {
            'supported_formats': list(self.supported_extensions.keys()),
            'total_osint_hashes': len(self.osint_checker.malicious_hashes),
            'analyzers': {
                'pdf': 'PDF Document Analyzer',
                'office': 'Office Document Analyzer (DOCX/XLSX)',
                'pe': 'Windows PE Executable Analyzer',
                'osint': 'OSINT Hash Database Checker'
            },
            'detection_methods': [
                'Hash-based OSINT lookup',
                'Pattern-based content analysis',
                'Structural analysis',
                'Behavioral indicator detection',
                'Heuristic scoring'
            ]
        } 

    def get_confidence_category(self, confidence_level: float) -> str:
        """
        Convert confidence level to human-readable category
        """
        if confidence_level >= 0.9:
            return "Very High"
        elif confidence_level >= 0.8:
            return "High"
        elif confidence_level >= 0.6:
            return "Medium"
        elif confidence_level >= 0.4:
            return "Low"
        else:
            return "Very Low" 