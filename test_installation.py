#!/usr/bin/env python3
"""
Project Sentinel - Installation Test Script
This script tests if all required packages can be imported successfully.
Run this after installation to verify everything is working.
"""

import sys
import importlib

# Required packages for Project Sentinel
REQUIRED_PACKAGES = [
    ('flask', 'Flask web framework'),
    ('flask_cors', 'Flask-CORS for cross-origin requests'),
    ('docx', 'python-docx for Word document processing'),
    ('openpyxl', 'openpyxl for Excel file processing'),
    ('pdfminer', 'pdfminer.six for PDF processing'),
    ('pefile', 'pefile for PE executable analysis'),
    ('sklearn', 'scikit-learn for machine learning'),
    ('numpy', 'numpy for numerical computing'),
    ('scipy', 'scipy for scientific computing'),
    ('requests', 'requests for HTTP requests'),
    ('reportlab', 'reportlab for PDF generation'),
    ('werkzeug', 'werkzeug for WSGI utilities'),
    ('jinja2', 'jinja2 for templating'),
]

def test_import(package_name, description):
    """Test if a package can be imported."""
    try:
        importlib.import_module(package_name)
        print(f"✅ {package_name:<20} - {description}")
        return True
    except ImportError as e:
        print(f"❌ {package_name:<20} - {description}")
        print(f"   Error: {e}")
        return False

def main():
    """Run installation tests."""
    print("🛡️  Project Sentinel - Installation Test")
    print("=" * 50)
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    print("=" * 50)
    
    failed_imports = []
    
    for package_name, description in REQUIRED_PACKAGES:
        if not test_import(package_name, description):
            failed_imports.append(package_name)
    
    print("=" * 50)
    
    if not failed_imports:
        print("🎉 All packages imported successfully!")
        print("✅ Installation is complete and ready to use.")
        print("\nYou can now run: python main.py")
    else:
        print(f"❌ {len(failed_imports)} package(s) failed to import:")
        for package in failed_imports:
            print(f"   - {package}")
        
        print("\n💡 Troubleshooting suggestions:")
        print("1. Ensure virtual environment is activated")
        print("2. Try: pip install -r requirements.txt")
        print("3. If that fails, try: pip install -r requirements-minimal.txt")
        print("4. For macOS compilation issues, try: pip install --only-binary=all -r requirements.txt")
        print("5. Install packages individually if needed")
        
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 