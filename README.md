# Project Sentinel: AI-Driven Malware Detection

**Authors:** Andrew Bentkowski and Ashley Dickens  
**Course:** ICTN6862  
**Implementation:** Complete functional system

## Overview

Project Sentinel is a comprehensive AI-driven malware detection system that analyzes common file formats (PDF, EXE, DOCX, XLSX) for potential security threats. The system combines Open Source Intelligence (OSINT) database lookups with **Claude AI-powered analysis** to provide intelligent, natural language explanations of security threats and comprehensive risk assessments.

## Features

### 🤖 **AI-Powered Analysis**
- **Claude AI Integration**: Uses Anthropic's Claude 3.5 Sonnet for intelligent threat analysis
- **Natural Language Explanations**: Human-readable security assessments and recommendations
- **Contextual Risk Analysis**: AI understands file patterns and provides specific threat insights
- **Dynamic Confidence Scoring**: AI-enhanced confidence ratings based on multiple analysis factors

### 🔍 **Core Capabilities**
- **Multi-format Support**: Analyzes PDF, EXE, DOCX, and XLSX files
- **Triple Analysis Approach**: 
  - OSINT database lookup for known malicious hashes
  - Rule-based pattern detection for suspicious indicators
  - **AI-driven threat assessment** with explanatory analysis
- **Web Interface**: User-friendly drag-and-drop interface with AI analysis sections
- **Real-time Analysis**: Fast processing with detailed technical and AI insights
- **Comprehensive Reporting**: Technical details + AI security recommendations
- **Educational Focus**: Demonstrates both traditional and AI-driven cybersecurity approaches

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
- **🤖 AI Analyzer**: Claude API integration for intelligent threat assessment and explanation

## 🤖 AI-Powered Components

### **AI Service Architecture**
```python
# Core AI integration using Anthropic Claude API
├── ai_service.py           # Claude API client and prompt management
├── ai_analyzer.py          # AI-enhanced analysis coordination
└── Enhanced Web Interface  # Displays AI insights and recommendations
```

### **Claude AI Integration Features**

#### **1. Intelligent Threat Assessment**
- **Natural Language Analysis**: Converts technical patterns into human-readable threat descriptions
- **Contextual Understanding**: AI comprehends file structure and suspicious pattern combinations
- **Risk Categorization**: Provides specific threat levels (LOW, MEDIUM, HIGH, CRITICAL)
- **Behavioral Analysis**: Explains potential malware behaviors and attack vectors

#### **2. AI-Enhanced Confidence Scoring**
```python
# AI confidence factors include:
- Pattern correlation strength
- Suspicious indicator clustering  
- File structure anomalies
- Known attack vector similarity
- Context-aware risk assessment
```

#### **3. Security Recommendations**
- **Immediate Actions**: Specific steps to handle suspicious files safely
- **System Protection**: Recommendations for preventing similar threats
- **User Guidance**: Clear instructions for non-technical users
- **Technical Details**: Advanced analysis for security professionals

#### **4. Real-Time AI Analysis**
```python
def ai_enhanced_analysis(file_data, rule_patterns):
    """
    Combines rule-based detection with AI analysis
    Returns: Enhanced threat assessment with explanations
    """
    # Extract suspicious patterns from rule-based analysis
    patterns = extract_suspicious_patterns(rule_patterns)
    
    # Send to Claude AI for contextual analysis
    ai_assessment = claude_api.analyze_threat_patterns(patterns, file_data)
    
    # Combine results for comprehensive analysis
    return merge_analysis_results(rule_based, ai_assessment)
```

### **AI Analysis Output Example**

When you upload a file, you'll see sections like:

**🤖 AI Security Analysis:**
```
This PDF exhibits several concerning characteristics typical of potentially 
malicious PDF documents. The presence of /OpenAction combined with JavaScript 
functionality creates an automatic execution risk upon opening...

Key Concerns:
1. JavaScript Implementation with app.launchURL capability
2. Automatic execution triggers (/OpenAction detected)  
3. Network communication potential
4. System interaction capabilities (printing functions)
```

**⚠️ Risk Factors:**
```
1. Remote Code Execution potential through JavaScript
2. Unauthorized network connections via app.launchURL
3. Automatic execution risk through /OpenAction
4. Possible system information gathering
```

**💡 AI Recommendations:**
```
IMMEDIATE: Open only in sandboxed environment, disable JavaScript
PROCEDURAL: Scan with updated antivirus, monitor network connections
LONG-TERM: Implement PDF security policies, deploy content filtering
```

## Installation and Setup

### Prerequisites
- Python 3.11 or later
- Modern web browser with JavaScript support
- At least 2GB RAM and 1GB available disk space

### Step 1: Clone the Repository
```bash
git clone https://github.com/nuclearashley/Project-Sentinel.git
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

#### Option A: Standard Installation (Recommended)
```bash
# Upgrade pip
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

#### Option B: If You Encounter Compilation Errors
If you get errors like "metadata-generation-failed" or Cython compilation errors, try:

```bash
# For macOS users - install build tools first
xcode-select --install

# Try installing with pre-compiled wheels only
pip install --only-binary=all -r requirements.txt
```

#### Option C: Minimal Installation (Troubleshooting)
If the standard installation fails, use the minimal requirements:

```bash
# Install minimal requirements
pip install -r requirements-minimal.txt
```

#### Option D: Manual Installation (Last Resort)
If all else fails, install packages individually:

```bash
# Install core packages first
pip install Flask Flask-CORS requests

# Install document processing
pip install python-docx openpyxl pdfminer.six pefile

# Install machine learning packages (may take longer)
pip install numpy scipy scikit-learn
```

### Step 4: Configure AI Integration

#### **🤖 Set Up Claude AI (Required for AI Features)**

**Option A: Interactive Setup (Recommended)**
```bash
# Run the interactive API key setup assistant
python setup_api_key.py
```

**Option B: Manual Setup**
```bash
# For macOS/Linux (zsh/bash):
echo 'export ANTHROPIC_API_KEY="your_api_key_here"' >> ~/.zshrc
source ~/.zshrc

# For Windows (Command Prompt):
setx ANTHROPIC_API_KEY "your_api_key_here"

# For Windows (PowerShell):
$env:ANTHROPIC_API_KEY="your_api_key_here"
[Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "your_api_key_here", "User")
```

**Option C: Quick Start Script**
```bash
# Use the provided startup script (includes API key setup)
chmod +x start_ai_enabled.sh
./start_ai_enabled.sh
```

#### **🔑 Getting Your Anthropic API Key**
1. Visit [Anthropic Console](https://console.anthropic.com/)
2. Create an account or sign in
3. Navigate to API Keys section
4. Create a new API key
5. Copy the key (starts with `sk-ant-api03-...`)

**💰 Cost Note**: Academic usage typically costs $2-5/month (~$0.02-0.05 per analysis)

### Step 5: Verify Installation

#### Quick Verification
```bash
# Check if all packages are installed correctly
pip list

# Verify AI configuration
python -c "from config import config; config.print_config_status()"
```

You should see:
```
🔧 Configuration Status:
   AI Enabled: ✅
   Anthropic Key: sk-ant-api...
   VirusTotal: ✅
   AI Model: claude-3-5-sonnet-20241022
```

#### Comprehensive Test (Recommended)
```bash
# Run the installation test script
python test_installation.py

# Test AI functionality specifically
python demo_ai_analysis.py
```

This script will test all package imports and AI integration, providing specific guidance if any components fail to load.

## Running the Application

### 🚀 **AI-Enabled Startup**

**Option A: One-Command Startup (Easiest)**
```bash
# Uses built-in API key configuration
./start_ai_enabled.sh
```

**Option B: Manual Startup**
```bash
# Make sure virtual environment is activated
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate     # On Windows

# Ensure API key is set (if not done permanently)
export ANTHROPIC_API_KEY="your_api_key_here"  # macOS/Linux
# or
set ANTHROPIC_API_KEY=your_api_key_here       # Windows

# Start the Flask server with AI enabled
python main.py
```

### ✅ **Verify AI is Working**

When you start the server, you should see:
```
✅ AI service initialized with Claude API
🛡️  Project Sentinel - AI-Driven Malware Detection
==================================================
🔧 Configuration Status:
   AI Enabled: ✅
   Anthropic Key: sk-ant-api...
   VirusTotal: ✅
   AI Model: claude-3-5-sonnet-20241022
Starting server on http://localhost:5001
```

**⚠️ If you see this instead:**
```
⚠️  WARNING: ANTHROPIC_API_KEY not found. AI analysis will be disabled.
```
Then your API key isn't configured properly. Use the setup instructions above.

### Access the Application
1. Open your web browser
2. Navigate to `http://localhost:5001`
3. The Project Sentinel interface should load with AI features enabled
4. Upload a file to see both rule-based AND AI-powered analysis

## Usage Instructions

### 🤖 **AI-Enhanced File Analysis**

1. **Upload a File**:
   - Drag and drop a file onto the upload area, or
   - Click the upload area to browse and select a file
   - Supported formats: PDF, EXE, DOCX, XLSX
   - Maximum file size: 50MB

2. **Start Analysis**:
   - Click the "🔍 Analyze File for Threats" button
   - Wait for the analysis to complete (typically 2-5 seconds)

3. **Review AI-Enhanced Results**:
   - **Green (Safe)**: File appears to be benign
   - **Yellow (Suspicious)**: File has some suspicious indicators
   - **Red (Malicious)**: File is likely malicious
   - **🤖 AI Analysis**: Natural language security assessment and recommendations

### Understanding AI-Enhanced Results

Each analysis provides **three layers of insight**:

#### **📊 Basic Analysis**
- **Threat Level**: Visual indicator of the risk level
- **Confidence Score**: AI-enhanced percentage indicating certainty
- **Hash**: SHA-256 hash of the analyzed file
- **Source**: Combined rule-based + AI analysis
- **Technical Details**: Expandable section with pattern analysis

#### **🤖 AI Security Analysis**
- **Threat Assessment**: AI categorization (LOW/MEDIUM/HIGH/CRITICAL)
- **Security Analysis**: Natural language explanation of threats
- **Risk Factors**: Specific security concerns identified by AI
- **Recommendations**: Actionable security advice

#### **🔍 Enhanced Features**
- **Contextual Understanding**: AI explains WHY patterns are suspicious
- **Attack Vector Analysis**: Describes potential malware behaviors
- **Confidence Factors**: AI explains its reasoning process
- **Comparison**: Rule-based vs AI analysis differences

### API Endpoints

The system also provides REST API endpoints:

- `GET /api/analysis/health` - Health check
- `POST /api/analysis/upload` - File upload and analysis
- `GET /api/analysis/stats` - Analysis engine statistics
- `GET /api/analysis/supported-formats` - Supported file formats

## File Analysis Details

### 🤖 **AI-Enhanced Analysis by File Type**

#### **PDF Files**
**Rule-Based Detection:**
- JavaScript detection (malicious scripts)
- Suspicious object identification
- URL pattern analysis
- Encoding pattern detection
- Object structure analysis

**+ AI Enhancement:**
- **Behavioral Analysis**: Explains what detected JavaScript could do
- **Risk Context**: Interprets pattern combinations (e.g., /OpenAction + app.launchURL)
- **Attack Vector Description**: Describes potential PDF-based attack methods
- **Remediation Advice**: Specific steps for safe PDF handling

#### **Office Documents (DOCX/XLSX)**
**Rule-Based Detection:**
- Macro pattern detection
- Suspicious API call identification
- Content pattern analysis
- XML structure examination
- Base64 encoding detection

**+ AI Enhancement:**
- **Macro Intent Analysis**: Explains what suspicious macros might accomplish
- **API Risk Assessment**: Contextualizes dangerous API combinations
- **Social Engineering Detection**: Identifies potential phishing elements
- **Business Context**: Understands document purpose vs suspicious features

#### **PE Executables (EXE)**
**Rule-Based Detection:**
- Import table analysis
- Suspicious API detection
- Packing/obfuscation detection
- String analysis
- PE structure examination

**+ AI Enhancement:**
- **Malware Family Recognition**: Identifies similar attack patterns
- **Capability Assessment**: Explains what the executable might do
- **Evasion Technique Analysis**: Describes obfuscation purposes
- **System Impact Prediction**: Forecasts potential system changes

#### **OSINT Database (Enhanced with AI Context)**
- Hash-based lookup against known malicious files
- Immediate identification of known threats
- Extensible to integrate with services like VirusTotal

## Testing

### 🤖 **AI Analysis Testing**

#### **Interactive AI Demo**
```bash
# Test AI analysis with a sample suspicious PDF
python demo_ai_analysis.py
```
This creates a test PDF with JavaScript and shows you:
- Rule-based analysis results
- AI-enhanced analysis
- Natural language explanations
- Security recommendations
- Cost estimation

#### **Manual AI Testing**
1. Start the application: `./start_ai_enabled.sh`
2. Upload test files from the `test_files/` directory
3. Compare results with and without AI enabled
4. Verify you see **🤖 AI Security Analysis** sections

### Traditional Testing

#### **Manual Testing**
1. Use the provided test files in the repository
2. Upload different file types to verify functionality
3. Test with known safe and suspicious files

#### **Automated Testing**
```bash
# Run the comprehensive test suite
python comprehensive_test.py

# Test AI integration specifically
python test_ai_integration.py
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

1. **Installation/Compilation Errors**:
   - **"metadata-generation-failed" or Cython errors**: Common on macOS
     ```bash
     # Solution 1: Install build tools
     xcode-select --install
     
     # Solution 2: Use pre-compiled wheels only
     pip install --only-binary=all -r requirements.txt
     
     # Solution 3: Use minimal requirements
     pip install -r requirements-minimal.txt
     
     # Solution 4: Install packages individually
     pip install Flask Flask-CORS requests python-docx openpyxl pdfminer.six pefile numpy scipy scikit-learn
     ```
   
   - **"No module named 'numpy'" during scikit-learn install**:
     ```bash
     # Install numpy first, then scikit-learn
     pip install numpy
     pip install scikit-learn
     ```

2. **Import Errors**:
   - Ensure virtual environment is activated
   - Verify all dependencies are installed: `pip install -r requirements.txt`
   - If packages are missing, try: `pip install -r requirements-minimal.txt`

3. **Port Already in Use**:
   - Change the port in `main.py`: `app.run(host='0.0.0.0', port=5002, debug=True)` (or any other available port)

4. **File Upload Fails**:
   - Check file size (must be under 50MB)
   - Verify file format is supported (PDF, EXE, DOCX, XLSX)

5. **Analysis Errors**:
   - Check console output for detailed error messages
   - Ensure file is not corrupted
   - Try with a different file to isolate the issue

6. **macOS-Specific Issues**:
   - **Command line tools not found**: Run `xcode-select --install`
   - **Architecture mismatch**: Use `pip install --upgrade pip setuptools wheel`
   - **Permission errors**: Ensure you're using a virtual environment

### Debug Mode
The application runs in debug mode by default, providing detailed error messages in the console.

## Development

### 🤖 **AI-Enhanced Project Structure**
```
Project-Sentinel/
├── main.py                    # Flask application entry point
├── config.py                  # 🤖 AI configuration management
├── requirements.txt           # Python dependencies (includes anthropic)
├── README.md                 # This file
├── 🤖 AI Setup & Demo Files:
│   ├── start_ai_enabled.sh   # One-command AI startup script
│   ├── setup_api_key.py      # Interactive API key configuration
│   ├── demo_ai_analysis.py   # AI analysis demonstration
│   ├── test_ai_integration.py # AI functionality testing
│   └── ACADEMIC_SETUP.md     # Academic user guide
├── src/                      # Source code
│   ├── __init__.py
│   ├── routes/               # API routes
│   │   ├── __init__.py
│   │   └── analysis.py       # Analysis endpoints (AI-enhanced)
│   └── services/             # Analysis services
│       ├── __init__.py
│       ├── 🤖 ai_service.py  # Claude API integration
│       ├── ai_analyzer.py    # Main coordinator (AI-enhanced)
│       ├── osint_checker.py  # OSINT database checker
│       ├── pdf_analyzer.py   # PDF analysis engine
│       ├── office_analyzer.py # Office document analyzer
│       └── pe_analyzer.py    # PE executable analyzer
├── static/                   # Frontend files
│   ├── index.html           # Main web interface (AI sections)
│   └── app.js               # Frontend JavaScript (AI results)
└── test_files/              # Test files for validation
```

### 🤖 **AI Integration Development**

#### **Adding AI Analysis to New File Types**
1. Create analyzer in `src/services/` (traditional pattern detection)
2. Add pattern extraction to `ai_analyzer.py`
3. Update AI prompts in `ai_service.py` for new file type
4. Enhance frontend to display AI results for new format

#### **Extending AI Capabilities**
```python
# Example: Adding new AI analysis type
def enhance_with_behavioral_analysis(patterns, file_metadata):
    """Add behavioral threat prediction to AI analysis"""
    prompt = f"""
    Analyze these suspicious patterns for behavioral threats:
    Patterns: {patterns}
    File Type: {file_metadata['type']}
    
    Predict likely malware behaviors and attack progression.
    """
    return claude_api.analyze(prompt)
```

#### **AI Configuration Management**
- **API Keys**: Managed in `config.py` with environment variable fallback
- **Model Selection**: Easy switching between Claude models
- **Cost Management**: Built-in token usage tracking and estimation
- **Rate Limiting**: Automatic handling of API rate limits

### Traditional Development Extensions

#### **Adding New File Types**
1. Create a new analyzer in `src/services/`
2. Add the analyzer to `ai_analyzer.py`
3. Update the supported extensions list  
4. Add appropriate patterns and detection logic
5. **🤖 Add AI enhancement prompts for new file type**

#### **Extending OSINT Integration**
1. Modify `osint_checker.py`
2. Add API keys and endpoints for services like VirusTotal
3. Implement proper error handling and rate limiting
4. **🤖 Enhance AI context with OSINT results**

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
- **🤖 AI Integration**: Anthropic Claude 3.5 Sonnet API for intelligent threat analysis
- **Libraries**: Flask, pdfminer, python-docx, openpyxl, pefile, scikit-learn, anthropic
- **Design**: Modern web interface with AI-enhanced analysis sections
- **Innovation**: Combining traditional cybersecurity with modern AI capabilities

## Disclaimer

**⚠️ IMPORTANT**: This tool is designed for educational and research purposes only. It should not be used as the sole method for determining file safety in production environments. Always consult with cybersecurity professionals for critical security decisions. If you suspect a file is malicious, do not execute it and contact your IT security team immediately.

The analysis provided by this system represents educated assessments based on pattern recognition and heuristic analysis. It may not detect all forms of malware, particularly sophisticated or zero-day threats. Users should maintain appropriate security practices and use this tool as one component of a comprehensive security strategy. 