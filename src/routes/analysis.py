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
                # Format response with new confidence system
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
                    'threat_level': ai_analyzer.get_threat_level(result['threat_score'], result['is_malicious'])
                }
                
                return jsonify(response), 200
            else:
                return jsonify({'error': result.get('error', 'Analysis failed')}), 500
        else:
            return jsonify({'error': 'Unsupported file type. Supported formats: PDF, EXE, DOCX, XLSX'}), 400
    
    except Exception as e:
        current_app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

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