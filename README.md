# Project Sentinel: AI-Driven Malware Detection

**Authors:** Andrew Bentkowski and Ashley Dickens  
**Course:** ICTN6862  
**Implementation:** Complete functional system

## Overview

Project Sentinel is a comprehensive AI-driven malware detection system that analyzes common file formats (PDF, EXE, DOCX, XLSX) for potential security threats. The system combines Open Source Intelligence (OSINT) database lookups with advanced AI-driven pattern analysis to provide immediate, educated assessments of file safety.

## Features

- **Multi-format Support**: Analyzes PDF, EXE, DOCX, and XLSX files
- **Dual Analysis Approach**: 
  - OSINT database lookup for known malicious hashes
  - AI-driven pattern analysis for unknown files
- **Confidence Scoring**: Provides detailed confidence ratings (0-100%)
- **Web Interface**: User-friendly drag-and-drop interface
- **Real-time Analysis**: Fast processing with detailed technical information
- **Comprehensive Reporting**: Detailed rationales and technical features
- **Educational Focus**: Designed for learning and research purposes

## System Architecture

### Frontend
- Modern web interface with drag-and-drop functionality
- Responsive design with professional styling
- Real-time progress indication and results display
- Color-coded threat levels with confidence bars

### Backend
- Flask-based REST API server
- Modular analysis engine with specialized analyzers
- Secure file handling with temporary file processing
- Comprehensive error handling and logging

### Analysis Engine
- **OSINT Checker**: Hash-based lookup against malicious file databases
- **PDF Analyzer**: Examines PDF documents for malicious JavaScript, suspicious objects, and encoding patterns
- **Office Analyzer**: Analyzes DOCX/XLSX files for macros, suspicious APIs, and content patterns
- **PE Analyzer**: Examines Windows executables for suspicious imports, packing, and structural anomalies

## Installation and Setup

### Prerequisites
- Python 3.11 or later
- Modern web browser with JavaScript support
- At least 2GB RAM and 1GB available disk space

### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd Project-Sentinel
```

### Step 2: Set Up Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

### Step 4: Verify Installation
```bash
# Check if all packages are installed correctly
pip list
```

## Running the Application

### Start the Server
```bash
# Make sure virtual environment is activated
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate     # On Windows

# Start the Flask server
python main.py
```

### Access the Application
1. Open your web browser
2. Navigate to `http://localhost:5001`
3. The Project Sentinel interface should load

## Usage Instructions

### Basic File Analysis
1. **Upload a File**:
   - Drag and drop a file onto the upload area, or
   - Click the upload area to browse and select a file
   - Supported formats: PDF, EXE, DOCX, XLSX
   - Maximum file size: 50MB

2. **Start Analysis**:
   - Click the "🔍 Analyze File for Threats" button
   - Wait for the analysis to complete (typically 2-5 seconds)

3. **Review Results**:
   - **Green (Safe)**: File appears to be benign
   - **Yellow (Suspicious)**: File has some suspicious indicators
   - **Red (Malicious)**: File is likely malicious

### Understanding Results

Each analysis provides:
- **Threat Level**: Visual indicator of the risk level
- **Confidence Score**: Percentage indicating certainty of the assessment
- **Hash**: SHA-256 hash of the analyzed file
- **Source**: Whether the result came from OSINT database or AI analysis
- **Rationale**: Detailed explanation of the findings
- **Technical Details**: Expandable section with feature analysis

### API Endpoints

The system also provides REST API endpoints:

- `GET /api/analysis/health` - Health check
- `POST /api/analysis/upload` - File upload and analysis
- `GET /api/analysis/stats` - Analysis engine statistics
- `GET /api/analysis/supported-formats` - Supported file formats

## File Analysis Details

### PDF Files
- JavaScript detection (malicious scripts)
- Suspicious object identification
- URL pattern analysis
- Encoding pattern detection
- Object structure analysis

### Office Documents (DOCX/XLSX)
- Macro pattern detection
- Suspicious API call identification
- Content pattern analysis
- XML structure examination
- Base64 encoding detection

### Windows Executables (EXE)
- Import table analysis
- Suspicious API detection
- Packing/obfuscation detection
- String analysis
- PE structure examination

### OSINT Database
- Hash-based lookup against known malicious files
- Immediate identification of known threats
- Extensible to integrate with services like VirusTotal

## Testing

### Manual Testing
1. Use the provided test files in the repository
2. Upload different file types to verify functionality
3. Test with known safe and suspicious files

### Automated Testing
```bash
# Run the comprehensive test suite (if test files are available)
python comprehensive_test.py
```

## Security Considerations

### File Safety
- All uploaded files are processed in isolated temporary storage
- Files are automatically deleted after analysis
- No permanent storage of analyzed files
- Safe parsing techniques prevent malicious code execution

### Limitations
- This is an educational tool, not a replacement for enterprise security solutions
- Always consult cybersecurity professionals for critical decisions
- The system provides indicators, not definitive malware identification
- Some sophisticated threats may not be detected

## Troubleshooting

### Common Issues

1. **Import Errors**:
   - Ensure virtual environment is activated
   - Verify all dependencies are installed: `pip install -r requirements.txt`

2. **Port Already in Use**:
   - Change the port in `main.py`: `app.run(host='0.0.0.0', port=5002, debug=True)` (or any other available port)

3. **File Upload Fails**:
   - Check file size (must be under 50MB)
   - Verify file format is supported (PDF, EXE, DOCX, XLSX)

4. **Analysis Errors**:
   - Check console output for detailed error messages
   - Ensure file is not corrupted
   - Try with a different file to isolate the issue

### Debug Mode
The application runs in debug mode by default, providing detailed error messages in the console.

## Development

### Project Structure
```
Project-Sentinel/
├── main.py                    # Flask application entry point
├── requirements.txt           # Python dependencies
├── README.md                 # This file
├── src/                      # Source code
│   ├── __init__.py
│   ├── routes/               # API routes
│   │   ├── __init__.py
│   │   └── analysis.py       # Analysis endpoints
│   └── services/             # Analysis services
│       ├── __init__.py
│       ├── ai_analyzer.py    # Main analysis coordinator
│       ├── osint_checker.py  # OSINT database checker
│       ├── pdf_analyzer.py   # PDF analysis engine
│       ├── office_analyzer.py # Office document analyzer
│       └── pe_analyzer.py    # PE executable analyzer
├── static/                   # Frontend files
│   ├── index.html           # Main web interface
│   └── app.js               # Frontend JavaScript
└── test files/              # Test files for validation
```

### Adding New File Types
1. Create a new analyzer in `src/services/`
2. Add the analyzer to `ai_analyzer.py`
3. Update the supported extensions list
4. Add appropriate patterns and detection logic

### Extending OSINT Integration
1. Modify `osint_checker.py`
2. Add API keys and endpoints for services like VirusTotal
3. Implement proper error handling and rate limiting

## Contributing

This is an academic project. For educational purposes, you can:
1. Fork the repository
2. Create feature branches
3. Submit pull requests with improvements
4. Report issues and bugs

## License

This project is for educational and research purposes only. Please respect the terms of use of any external services integrated with the system.

## Acknowledgments

- **Course**: ICTN6862 - AI Applications in Cybersecurity
- **Students**: Andrew Bentkowski and Ashley Dickens
- **Libraries**: Flask, pdfminer, python-docx, openpyxl, pefile, scikit-learn
- **Design**: Modern web interface with professional styling

## Disclaimer

**⚠️ IMPORTANT**: This tool is designed for educational and research purposes only. It should not be used as the sole method for determining file safety in production environments. Always consult with cybersecurity professionals for critical security decisions. If you suspect a file is malicious, do not execute it and contact your IT security team immediately.

The analysis provided by this system represents educated assessments based on pattern recognition and heuristic analysis. It may not detect all forms of malware, particularly sophisticated or zero-day threats. Users should maintain appropriate security practices and use this tool as one component of a comprehensive security strategy. 