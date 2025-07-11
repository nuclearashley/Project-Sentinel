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
        analyzeBtn.textContent = '🔍 Analyze File for Threats';
        loading.style.display = 'none';
    }
}

function displayResults(result) {
    const resultsContainer = document.getElementById('results');
    
    let resultClass = 'result-safe';
    let resultIcon = '✅';
    let resultTitle = 'File appears to be safe';
    
    if (result.is_malicious) {
        if (result.confidence > 0.7) {
            resultClass = 'result-malicious';
            resultIcon = '🚨';
            resultTitle = 'Malicious file detected!';
        } else {
            resultClass = 'result-warning';
            resultIcon = '⚠️';
            resultTitle = 'Potentially suspicious file';
        }
    }
    
    const confidencePercent = Math.round(result.confidence * 100);
    const confidenceColor = result.is_malicious ? 
        (result.confidence > 0.7 ? '#dc3545' : '#ffc107') : '#28a745';
    
    resultsContainer.innerHTML = `
        <div class="result-card ${resultClass}">
            <div class="result-title">${resultIcon} ${resultTitle}</div>
            <p><strong>File:</strong> ${result.filename}</p>
            <p><strong>Hash:</strong> ${result.hash}</p>
            <p><strong>Source:</strong> ${result.source}</p>
            <p><strong>Confidence:</strong> ${confidencePercent}%</p>
            
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: ${confidencePercent}%; background-color: ${confidenceColor};"></div>
            </div>
            
            <p><strong>Analysis:</strong></p>
            <p>${result.rationale}</p>
            
            ${result.features ? `
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; font-weight: bold;">Technical Details</summary>
                    <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; font-size: 0.9em;">${JSON.stringify(result.features, null, 2)}</pre>
                </details>
            ` : ''}
            
            ${result.details ? `
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; font-weight: bold;">OSINT Details</summary>
                    <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; font-size: 0.9em;">${JSON.stringify(result.details, null, 2)}</pre>
                </details>
            ` : ''}
        </div>
        
        <div style="background: #e9ecef; padding: 15px; border-radius: 10px; font-size: 0.9em; color: #666;">
            <strong>⚠️ Important:</strong> This analysis is for educational purposes. Always consult with security professionals for critical decisions. If you suspect a file is malicious, do not execute it and contact your IT security team.
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

