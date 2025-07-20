let selectedFile = null;

const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const analyzeBtn = document.getElementById('analyzeBtn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const error = document.getElementById('error');

// Hash analysis elements
const hashInput = document.getElementById('hashInput');
const hashType = document.getElementById('hashType');
const analyzeHashBtn = document.getElementById('analyzeHashBtn');

// Drag and drop functionality
uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('dragover');
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragover');
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});

uploadArea.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

function handleFileSelect(file) {
    const allowedExtensions = ['.pdf', '.exe', '.docx', '.xlsx'];
    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    
    if (!allowedExtensions.includes(fileExtension)) {
        showError('Unsupported file type. Please select a PDF, EXE, DOCX, or XLSX file.');
        return;
    }
    
    if (file.size > 50 * 1024 * 1024) { // 50MB
        showError('File too large. Maximum size is 50MB.');
        return;
    }
    
    selectedFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    
    fileInfo.style.display = 'block';
    analyzeBtn.style.display = 'block';
    hideError();
    hideResults();
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

analyzeBtn.addEventListener('click', analyzeFile);

// Hash analysis event listeners
analyzeHashBtn.addEventListener('click', analyzeHash);
hashInput.addEventListener('input', validateHashInput);
hashType.addEventListener('change', validateHashInput);

async function analyzeFile() {
    if (!selectedFile) {
        showError('Please select a file first.');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', selectedFile);
    
    // Show loading state
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Analyzing...';
    loading.style.display = 'block';
    hideError();
    hideResults();
    
    try {
        const response = await fetch('/api/analysis/upload', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            displayResults(result);
        } else {
            showError(result.error || 'Analysis failed. Please try again.');
        }
    } catch (err) {
        showError('Network error. Please check your connection and try again.');
        console.error('Analysis error:', err);
    } finally {
        // Reset button state
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = 'Run Analysis';
        loading.style.display = 'none';
    }
}

function validateHashInput() {
    const hash = hashInput.value.trim();
    const selectedType = hashType.value;
    
    // Clear previous validation styling
    hashInput.style.borderColor = '#ddd';
    analyzeHashBtn.disabled = false;
    
    if (!hash) {
        analyzeHashBtn.disabled = true;
        return;
    }
    
    // Check length based on hash type
    let expectedLength = 64; // SHA-256 default
    if (selectedType === 'md5') expectedLength = 32;
    else if (selectedType === 'sha1') expectedLength = 40;
    
    if (hash.length !== expectedLength) {
        hashInput.style.borderColor = '#dc3545';
        analyzeHashBtn.disabled = true;
        return;
    }
    
    // Check if hash contains only hex characters
    if (!/^[0-9a-fA-F]+$/.test(hash)) {
        hashInput.style.borderColor = '#dc3545';
        analyzeHashBtn.disabled = true;
        return;
    }
    
    // Valid hash
    hashInput.style.borderColor = '#28a745';
    analyzeHashBtn.disabled = false;
}

async function analyzeHash() {
    const hash = hashInput.value.trim();
    const selectedType = hashType.value;
    
    if (!hash) {
        showError('Please enter a hash to analyze.');
        return;
    }
    
    // Validate hash format
    validateHashInput();
    if (analyzeHashBtn.disabled) {
        showError('Please enter a valid hash format.');
        return;
    }
    
    // Show loading state
    analyzeHashBtn.disabled = true;
    analyzeHashBtn.textContent = 'Analyzing...';
    loading.style.display = 'block';
    hideError();
    hideResults();
    
    try {
        const response = await fetch('/api/analysis/hash', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                hash: hash,
                hash_type: selectedType
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            displayResults(result);
        } else {
            showError(result.error || 'Hash analysis failed. Please try again.');
        }
    } catch (err) {
        showError('Network error. Please check your connection and try again.');
        console.error('Hash analysis error:', err);
    } finally {
        // Reset button state
        analyzeHashBtn.disabled = false;
        analyzeHashBtn.textContent = '🔍 Analyze Hash';
        loading.style.display = 'none';
    }
}

function displayResults(result) {
    const resultsContainer = document.getElementById('results');
    
    let resultClass = 'result-safe';
    let resultIcon = 'SAFE';
    let resultTitle = 'File appears to be safe';
    
    if (result.is_malicious) {
        if (result.threat_score > 0.7) {
            resultClass = 'result-malicious';
            resultIcon = 'THREAT';
            resultTitle = 'Potential threat detected';
        } else {
            resultClass = 'result-warning';
            resultIcon = 'WARNING';
            resultTitle = 'File may be suspicious';
        }
    }
    
    const confidencePercent = Math.round(result.confidence_level * 100);
    const threatPercent = Math.round(result.threat_score * 100);
    
    // Color for confidence bar (green = high confidence, red = low confidence)
    const confidenceColor = result.confidence_level > 0.8 ? '#28a745' : 
                           result.confidence_level > 0.6 ? '#ffc107' : '#dc3545';
    
    // Color for threat bar (red = high threat, green = low threat)
    const threatColor = result.threat_score > 0.7 ? '#dc3545' : 
                       result.threat_score > 0.4 ? '#ffc107' : '#28a745';
    
    // Determine if this is a hash analysis result
    const isHashAnalysis = result.hash_type || result.filename.includes('Hash Analysis');
    
    // Check if this is a VirusTotal result
    const isVirusTotalResult = result.details && result.details.source === 'VirusTotal API';
    
    // Generate additional info for VirusTotal results
    let additionalInfo = '';
    if (isVirusTotalResult && result.details) {
        const details = result.details;
        if (details.detection_ratio) {
            additionalInfo += `<p><strong>Detection Ratio:</strong> ${details.detection_ratio}</p>`;
        }
        if (details.total_engines) {
            additionalInfo += `<p><strong>Total Engines:</strong> ${details.total_engines}</p>`;
        }
        if (details.reputation !== undefined) {
            additionalInfo += `<p><strong>Reputation Score:</strong> ${details.reputation}</p>`;
        }
        if (details.last_analysis_date) {
            const date = new Date(details.last_analysis_date * 1000);
            additionalInfo += `<p><strong>Last Analyzed:</strong> ${date.toLocaleDateString()}</p>`;
        }
    }
    
    resultsContainer.innerHTML = `
        <div class="result-card ${resultClass}">
            <div class="result-title">[${resultIcon}] ${resultTitle}</div>
            ${isHashAnalysis ? 
                `<p><strong>Hash Type:</strong> ${result.hash_type || 'SHA-256'}</p>` :
                `<p><strong>File:</strong> ${result.filename}</p>`
            }
            <p><strong>Hash:</strong> ${result.hash}</p>
            <p><strong>Analysis Method:</strong> ${result.source}</p>
            <p><strong>Confidence:</strong> ${confidencePercent}% (${result.confidence_category})</p>
            
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: ${confidencePercent}%; background-color: ${confidenceColor};"></div>
            </div>
            
            ${result.threat_score > 0 ? `
                <p><strong>Threat Level:</strong> ${threatPercent}%</p>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${threatPercent}%; background-color: ${threatColor};"></div>
                </div>
            ` : ''}
            
            ${additionalInfo}
            
            <p><strong>Analysis Results:</strong></p>
            <p>${result.rationale}</p>
            
            ${result.ai_available && result.ai_security_analysis ? `
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; font-weight: bold;">🤖 AI Security Analysis</summary>
                    <div style="margin-top: 10px; padding: 10px; background: #f0f7ff; border-left: 4px solid #007bff; border-radius: 5px;">
                        <p><strong>AI Threat Assessment:</strong> ${result.ai_threat_assessment || 'N/A'}</p>
                        <p><strong>Security Analysis:</strong></p>
                        <p>${result.ai_security_analysis}</p>
                        ${result.ai_risk_factors ? `
                            <p><strong>Risk Factors:</strong></p>
                            <p>${result.ai_risk_factors}</p>
                        ` : ''}
                        ${result.ai_recommendations ? `
                            <p><strong>Recommendations:</strong></p>
                            <p>${result.ai_recommendations}</p>
                        ` : ''}
                        ${result.ai_confidence > 0 ? `
                            <p><strong>AI Confidence:</strong> ${Math.round(result.ai_confidence * 100)}%</p>
                        ` : ''}
                    </div>
                </details>
            ` : result.ai_available === false ? `
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; font-weight: bold;">🤖 AI Analysis (Unavailable)</summary>
                    <div style="margin-top: 10px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 5px;">
                        <p><strong>AI Service Status:</strong> Not configured</p>
                        <p>To enable AI-powered threat analysis, set your ANTHROPIC_API_KEY environment variable.</p>
                        <p>Currently using rule-based analysis only.</p>
                    </div>
                </details>
            ` : ''}
            
            ${result.confidence_factors && result.confidence_factors.length > 0 ? `
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; font-weight: bold;">What makes us confident about this result?</summary>
                    <ul style="margin-top: 10px;">
                        ${result.confidence_factors.map(factor => `<li>${factor}</li>`).join('')}
                    </ul>
                </details>
            ` : ''}
            
            ${result.features ? `
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; font-weight: bold;">Technical Details</summary>
                    <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; font-size: 0.9em;">${JSON.stringify(result.features, null, 2)}</pre>
                </details>
            ` : ''}
            
            ${result.details ? `
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; font-weight: bold;">Database Results</summary>
                    <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; font-size: 0.9em;">${JSON.stringify(result.details, null, 2)}</pre>
                </details>
            ` : ''}
        </div>
        
        <div style="background: #e9ecef; padding: 15px; border-radius: 10px; font-size: 0.9em; color: #666;">
            <strong>Important:</strong> This analysis is for educational and research purposes only. 
            Do not make critical security decisions based on these results alone.
            ${isHashAnalysis ? '<br><br><strong>Hash Analysis Note:</strong> This analysis checks against local OSINT database and VirusTotal. For comprehensive analysis, consider uploading the actual file.' : ''}
            ${isVirusTotalResult ? '<br><br><strong>VirusTotal Note:</strong> Results include real-time threat intelligence from VirusTotal\'s network of security vendors.' : ''}
        </div>
    `;
    
    results.style.display = 'block';
}

function showError(message) {
    error.textContent = message;
    error.style.display = 'block';
}

function hideError() {
    error.style.display = 'none';
}

function hideResults() {
    results.style.display = 'none';
} 