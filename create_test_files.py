#!/usr/bin/env python3
"""
Script to create test files for Project Sentinel validation
"""

import os
from docx import Document
from openpyxl import Workbook
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import hashlib

def create_safe_pdf():
    """Create a safe PDF file"""
    filename = "safe_document.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "Project Sentinel Test Document")
    c.drawString(100, 720, "This is a safe PDF document for testing purposes.")
    c.drawString(100, 690, "It contains no malicious content or suspicious patterns.")
    c.drawString(100, 660, "This should be classified as safe by the analysis engine.")
    c.save()
    print(f"Created: {filename}")
    return filename

def create_suspicious_pdf():
    """Create a PDF with suspicious patterns"""
    filename = "suspicious_document.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "Suspicious Test Document")
    c.drawString(100, 720, "This document contains suspicious patterns:")
    c.drawString(100, 690, "/JavaScript eval(unescape('%75%6E%65%73%63%61%70%65'))")
    c.drawString(100, 660, "/OpenAction /Launch cmd.exe")
    c.drawString(100, 630, "String.fromCharCode(malicious_code)")
    c.save()
    print(f"Created: {filename}")
    return filename

def create_safe_docx():
    """Create a safe DOCX file"""
    filename = "safe_document.docx"
    doc = Document()
    doc.add_heading('Project Sentinel Test Document', 0)
    doc.add_paragraph('This is a safe Word document for testing purposes.')
    doc.add_paragraph('It contains normal business content without any suspicious elements.')
    doc.add_paragraph('This should be classified as safe by the analysis engine.')
    doc.save(filename)
    print(f"Created: {filename}")
    return filename

def create_suspicious_docx():
    """Create a DOCX with suspicious patterns"""
    filename = "suspicious_document.docx"
    doc = Document()
    doc.add_heading('Suspicious Test Document', 0)
    doc.add_paragraph('This document contains suspicious patterns:')
    doc.add_paragraph('Auto_Open() Shell.Application CreateObject("WScript.Shell")')
    doc.add_paragraph('cmd.exe powershell.exe base64encoded_payload')
    doc.add_paragraph('Document_Open() macro execution')
    doc.save(filename)
    print(f"Created: {filename}")
    return filename

def create_safe_xlsx():
    """Create a safe XLSX file"""
    filename = "safe_spreadsheet.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.title = "Test Data"
    ws['A1'] = "Project Sentinel Test Spreadsheet"
    ws['A2'] = "This is safe test data"
    ws['A3'] = "Column A"
    ws['B3'] = "Column B"
    ws['A4'] = "Data 1"
    ws['B4'] = "Value 1"
    ws['A5'] = "Data 2"
    ws['B5'] = "Value 2"
    wb.save(filename)
    print(f"Created: {filename}")
    return filename

def create_suspicious_xlsx():
    """Create an XLSX with suspicious patterns"""
    filename = "suspicious_spreadsheet.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.title = "Suspicious Data"
    ws['A1'] = "Suspicious Test Spreadsheet"
    ws['A2'] = "Auto_Open macro detected"
    ws['A3'] = "Shell.Application"
    ws['A4'] = "CreateObject WScript.Shell"
    ws['A5'] = "cmd.exe execution"
    ws['A6'] = "powershell -enc base64payload"
    ws['A7'] = "http://malicious-domain.com/payload"
    wb.save(filename)
    print(f"Created: {filename}")
    return filename

def create_known_malicious_hash():
    """Create a file with a known malicious hash for OSINT testing"""
    filename = "known_malicious.txt"
    # Create content that will hash to one of our test hashes
    content = "test"  # This will create hash: 098f6bcd4621d373cade4e832627b4f6
    with open(filename, 'w') as f:
        f.write(content)
    
    # Verify the hash
    with open(filename, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    print(f"Created: {filename} (Hash: {file_hash})")
    return filename

def main():
    print("Creating test files for Project Sentinel...")
    
    # Create test files
    files_created = []
    files_created.append(create_safe_pdf())
    files_created.append(create_suspicious_pdf())
    files_created.append(create_safe_docx())
    files_created.append(create_suspicious_docx())
    files_created.append(create_safe_xlsx())
    files_created.append(create_suspicious_xlsx())
    files_created.append(create_known_malicious_hash())
    
    print(f"\nCreated {len(files_created)} test files:")
    for file in files_created:
        size = os.path.getsize(file)
        print(f"  - {file} ({size} bytes)")
    
    print("\nTest files are ready for validation!")

if __name__ == "__main__":
    main()

