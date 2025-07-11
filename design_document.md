# Project Sentinel: System Design

## 1. Introduction

Project Sentinel is a tool designed to help users assess the risk of malicious files. It will accept PDF, EXE, DOCX, and XLSX files, and provide a confidence-based malware detection service. This document outlines the system architecture and design for this project.

## 2. System Architecture

The system will be composed of three main components:

*   **Frontend:** A user-friendly web interface for file uploads.
*   **Backend:** A server to manage the analysis workflow.
*   **Analysis Engine:** The core component responsible for malware detection.



### 2.1 Frontend

The frontend will be a web-based interface, allowing users to easily upload files for analysis. It will display the analysis results, including the likelihood of a file being malicious and the rationale behind the assessment. The interface should be intuitive and provide clear feedback to the user.

## 3. Analysis Engine Details

### 3.1 Initial Threat Assessment (Hash-Based)

Upon file upload, the system will first calculate the hash of the file. This hash will then be compared against open-source intelligence (OSINT) databases of known malicious file hashes. If a match is found, the system will immediately flag the file as malicious and communicate this to the user.

### 3.2 AI-Driven Analysis (for unknown threats)

If no match is found in the OSINT databases, the system will proceed with AI-driven analysis. This component will be responsible for assigning a rating of the likelihood that a file is malicious and providing a rationale for its thinking. The AI model will need to be trained on a diverse dataset of both benign and malicious files across the supported file formats (PDF, EXE, DOCX, XLSX).

#### 3.2.1 Feature Extraction

For each file type, relevant features will need to be extracted. For example:

*   **PDF/DOCX/XLSX:** Metadata, embedded scripts, macros, suspicious links, unusual object structures.
*   **EXE:** API calls, imported libraries, section entropy, packed status, string analysis.

#### 3.2.2 AI Model Selection

Given the nature of the problem (classification), various machine learning models could be considered, such as:

*   **Supervised Learning Models:** Support Vector Machines (SVM), Random Forests, Gradient Boosting Machines (GBM), or Neural Networks.

The choice of the model will depend on the complexity of the features and the desired accuracy and interpretability.

#### 3.2.3 Confidence Scoring and Rationale Generation

The AI model will output a confidence score indicating the likelihood of a file being malicious. Additionally, the system should generate a human-readable rationale explaining why the AI classified the file as such. This could involve highlighting specific extracted features that contributed to the classification.



### 2.2 Backend

The backend will serve as the central orchestrator, handling file uploads, managing the analysis queue, interacting with the OSINT database, invoking the AI analysis engine, and storing results. It will expose an API for the frontend to communicate with.

**Key functionalities of the Backend:**

*   **File Upload Handling:** Securely receive and store uploaded files.
*   **Task Queuing:** Manage a queue of files awaiting analysis to ensure efficient processing.
*   **OSINT Integration:** Interface with external OSINT databases (e.g., VirusTotal, Hybrid Analysis) to perform hash lookups.
*   **AI Engine Orchestration:** Trigger the AI analysis process and feed it the extracted features.
*   **Result Storage:** Persist analysis results, including confidence scores and rationales.
*   **API Endpoint:** Provide RESTful APIs for the frontend to:
    *   Upload files.
    *   Check analysis status.
    *   Retrieve analysis results.

## 4. Workflow

1.  **User Uploads File:** The user uploads a file through the frontend.
2.  **Backend Receives File:** The backend receives the file and stores it temporarily.
3.  **Hash Calculation:** The backend calculates the file's hash.
4.  **OSINT Lookup:** The backend queries OSINT databases with the calculated hash.
5.  **Known Threat Detected:** If a match is found, the backend immediately returns a 'malicious' verdict and rationale to the frontend.
6.  **AI Analysis Triggered:** If no match is found, the backend sends the file to the AI Analysis Engine.
7.  **Feature Extraction & AI Prediction:** The AI Analysis Engine extracts relevant features and uses its trained model to predict the likelihood of the file being malicious.
8.  **Rationale Generation:** The AI Analysis Engine generates a rationale for its prediction.
9.  **Results to Backend:** The AI Analysis Engine sends the confidence score and rationale back to the backend.
10. **Results to Frontend:** The backend stores the results and sends them to the frontend for display to the user.

## 5. Technologies to be Used

*   **Frontend:** React.js (for interactive UI)
*   **Backend:** Flask (Python web framework)
*   **AI/ML:** scikit-learn, TensorFlow/Keras, or PyTorch (for model development and deployment)
*   **OSINT Integration:** Requests library (for API calls to OSINT services)
*   **File Processing:** Libraries specific to PDF, EXE, DOCX, XLSX parsing (e.g., `python-docx`, `openpyxl`, `pefile`, `pdfminer.six`)
*   **Database:** SQLite (for simplicity in prototype, can be upgraded to PostgreSQL/MySQL)

## 6. Future Enhancements

*   Integration with more OSINT sources.
*   Real-time analysis capabilities.
*   User authentication and authorization.
*   Detailed reporting and logging.
*   Support for additional file formats.
*   Containerization (Docker) for easier deployment.


