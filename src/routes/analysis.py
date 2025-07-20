from flask import Blueprint, request, jsonify, current_app
import os
import time
from werkzeug.utils import secure_filename
from ..services.ai_analyzer import AIAnalyzer

# Create blueprint
analysis_bp = Blueprint('analysis', __name__)

# Initialize AI analyzer
ai_analyzer = AIAnalyzer()

def allowed_file(filename):
    """Check if file has allowed extension"""
    return ai_analyzer.is_supported_file(filename)

@analysis_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Project Sentinel Analysis API',
        'supported_formats': ai_analyzer.get_analysis_statistics()['supported_formats'],
        'timestamp': time.time()
    })

@analysis_bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file size (Flask already handles MAX_CONTENT_LENGTH)
        if file and allowed_file(file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)
            
            # Perform analysis
            start_time = time.time()
            result = ai_analyzer.analyze_uploaded_file(file)
            analysis_time = time.time() - start_time
            
            if result.get('success', False):
                # Format response with new confidence system and AI enhancements
                response = {
                    'filename': result['filename'],
                    'hash': result['hash'],
                    'is_malicious': result['is_malicious'],
                    'threat_score': result['threat_score'],
                    'confidence_level': result['confidence_level'],
                    'confidence_category': result['confidence_category'],
                    'confidence_factors': result['confidence_factors'],
                    'confidence': result['confidence_level'],  # Keep for backward compatibility
                    'source': result['source'],
                    'rationale': result['rationale'],
                    'features': result['features'],
                    'details': result.get('details'),
                    'analysis_time': analysis_time,
                    'threat_level': ai_analyzer.get_threat_level(result['threat_score'], result['is_malicious']),
                    # AI-enhanced results
                    'ai_threat_assessment': result.get('ai_threat_assessment'),
                    'ai_security_analysis': result.get('ai_security_analysis'),
                    'ai_risk_factors': result.get('ai_risk_factors'),
                    'ai_recommendations': result.get('ai_recommendations'),
                    'ai_confidence': result.get('ai_confidence', 0.0),
                    'ai_available': ai_analyzer.ai_service.is_available()
                }
                
                return jsonify(response), 200
            else:
                return jsonify({'error': result.get('error', 'Analysis failed')}), 500
        else:
            return jsonify({'error': 'Unsupported file type. Supported formats: PDF, EXE, DOCX, XLSX'}), 400
    
    except Exception as e:
        current_app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@analysis_bp.route('/hash', methods=['POST'])
def analyze_hash():
    """Handle hash analysis"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        file_hash = data.get('hash', '').strip()
        hash_type = data.get('hash_type', 'sha256').lower()
        
        if not file_hash:
            return jsonify({'error': 'No hash provided'}), 400
        
        # Validate hash format
        if hash_type == 'sha256' and len(file_hash) != 64:
            return jsonify({'error': 'Invalid SHA-256 hash format. Expected 64 characters.'}), 400
        elif hash_type == 'md5' and len(file_hash) != 32:
            return jsonify({'error': 'Invalid MD5 hash format. Expected 32 characters.'}), 400
        elif hash_type == 'sha1' and len(file_hash) != 40:
            return jsonify({'error': 'Invalid SHA-1 hash format. Expected 40 characters.'}), 400
        
        # Validate hash characters (hex only)
        try:
            int(file_hash, 16)
        except ValueError:
            return jsonify({'error': 'Invalid hash format. Hash must contain only hexadecimal characters (0-9, a-f).'}), 400
        
        # Perform hash analysis using OSINT checker (now includes VirusTotal)
        start_time = time.time()
        osint_result = ai_analyzer.osint_checker.check_osint_databases(file_hash)
        analysis_time = time.time() - start_time
        
        is_malicious, source_info, details = osint_result
        
        # Format response based on the source
        if is_malicious:
            if details and details.get('source') == 'VirusTotal API':
                # VirusTotal detected malware
                threat_score = min(1.0, details.get('malicious_count', 1) / max(details.get('total_engines', 1), 1))
                confidence_level = 0.95
                confidence_factors = [
                    f"VirusTotal: {details.get('malicious_count', 0)}/{details.get('total_engines', 0)} engines detected malware",
                    "Real-time threat intelligence from VirusTotal"
                ]
                if details.get('malicious_engines'):
                    confidence_factors.append(f"Detected by: {', '.join(details['malicious_engines'])}")
            else:
                # Local database detected malware
                threat_score = 1.0
                confidence_level = 0.95
                confidence_factors = ["Known malicious hash in local OSINT database"]
            
            rationale = source_info
            source = details.get('source', 'OSINT Database') if details else 'OSINT Database'
            
        else:
            if details and details.get('source') == 'VirusTotal API':
                # VirusTotal checked and found clean
                threat_score = 0.0
                confidence_level = 0.85
                confidence_factors = [
                    f"VirusTotal: {details.get('total_engines', 0)} engines checked, none detected malware",
                    "Real-time threat intelligence from VirusTotal"
                ]
                if details.get('reputation', 0) > 0:
                    confidence_factors.append(f"Positive reputation score: {details['reputation']}")
                rationale = source_info
                source = "VirusTotal API"
                
            elif details and details.get('status') == 'not_found':
                # Hash not found in VirusTotal
                threat_score = 0.0
                confidence_level = 0.6
                confidence_factors = [
                    "Hash not found in VirusTotal database",
                    "No local OSINT matches"
                ]
                rationale = source_info
                source = "VirusTotal API"
                
            else:
                # Only local check performed
                threat_score = 0.0
                confidence_level = 0.8
                confidence_factors = ["No matches in local OSINT database"]
                rationale = "No matches found in OSINT databases"
                source = "Local OSINT Database"
        
        response = {
            'filename': f'Hash Analysis ({hash_type.upper()})',
            'hash': file_hash,
            'hash_type': hash_type.upper(),
            'is_malicious': is_malicious,
            'threat_score': threat_score,
            'confidence_level': confidence_level,
            'confidence_category': ai_analyzer.get_confidence_category(confidence_level),
            'confidence_factors': confidence_factors,
            'source': source,
            'rationale': rationale,
            'features': None,
            'details': details,
            'analysis_time': analysis_time,
            'threat_level': ai_analyzer.get_threat_level(threat_score, is_malicious),
            # AI service availability for hash analysis
            'ai_available': ai_analyzer.ai_service.is_available(),
            'ai_threat_assessment': 'HASH_ONLY_ANALYSIS',  # Hash analysis doesn't use AI
            'ai_security_analysis': 'Hash-based analysis only - no content analysis performed',
            'ai_risk_factors': None,
            'ai_recommendations': None,
            'ai_confidence': 0.0
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        current_app.logger.error(f"Hash analysis error: {str(e)}")
        return jsonify({'error': f'Hash analysis failed: {str(e)}'}), 500

@analysis_bp.route('/stats', methods=['GET'])
def get_statistics():
    """Get analysis engine statistics"""
    try:
        stats = ai_analyzer.get_analysis_statistics()
        return jsonify(stats), 200
    except Exception as e:
        current_app.logger.error(f"Stats error: {str(e)}")
        return jsonify({'error': f'Failed to get statistics: {str(e)}'}), 500

@analysis_bp.route('/supported-formats', methods=['GET'])
def get_supported_formats():
    """Get list of supported file formats"""
    try:
        formats = ai_analyzer.get_analysis_statistics()['supported_formats']
        return jsonify({
            'supported_formats': formats,
            'description': 'File formats supported by Project Sentinel'
        }), 200
    except Exception as e:
        current_app.logger.error(f"Supported formats error: {str(e)}")
        return jsonify({'error': f'Failed to get supported formats: {str(e)}'}), 500

@analysis_bp.route('/test', methods=['POST'])
def test_analysis():
    """Test endpoint for debugging"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        return jsonify({
            'message': 'Test endpoint working',
            'received_data': data,
            'analyzer_ready': ai_analyzer is not None,
            'timestamp': time.time()
        }), 200
    except Exception as e:
        current_app.logger.error(f"Test error: {str(e)}")
        return jsonify({'error': f'Test failed: {str(e)}'}), 500 