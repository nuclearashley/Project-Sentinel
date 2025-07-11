#!/usr/bin/env python3
"""
System validation script for Project Sentinel
Tests the malware detection system against known test files
"""

import os
import json
import time
import requests
from typing import Dict, List, Any
from src.services.ai_analyzer import AIAnalyzer

# Test expectations
TEST_EXPECTATIONS = {
    'simple_form.pdf': {
        'should_be_malicious': False,
        'expected_confidence': 'Medium',  # Should be confident it's safe
        'notes': 'Simple PDF with basic content - should be safe'
    },
    'sample_document.docx': {
        'should_be_malicious': False,
        'expected_confidence': 'High',  # Should be very confident it's safe
        'notes': 'Normal Word document with business content'
    },
    'sample_spreadsheet.xlsx': {
        'should_be_malicious': False,
        'expected_confidence': 'High',  # Should be confident it's safe
        'notes': 'Excel workbook with formulas and normal data'
    },
    'document_with_links.pdf': {
        'should_be_malicious': False,
        'expected_confidence': 'Medium',  # Might be slightly lower due to URLs
        'notes': 'PDF with legitimate URLs - should not trigger false positives'
    },
    'empty_file.pdf': {
        'should_be_malicious': False,
        'expected_confidence': 'Low',  # Low confidence due to empty file
        'notes': 'Empty file - should handle gracefully'
    },
    'large_spreadsheet.xlsx': {
        'should_be_malicious': False,
        'expected_confidence': 'High',  # Should be confident it's safe
        'notes': 'Large Excel file with many formulas'
    }
}

def analyze_file_locally(analyzer: AIAnalyzer, file_path: str) -> Dict[str, Any]:
    """Analyze a file using the local analyzer"""
    try:
        filename = os.path.basename(file_path)
        result = analyzer.analyze_file(file_path, filename)
        return result
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'filename': os.path.basename(file_path)
        }

def analyze_file_via_api(file_path: str, api_url: str = 'http://localhost:5001/api/analysis/upload') -> Dict[str, Any]:
    """Analyze a file via the web API"""
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(api_url, files=files, timeout=30)
            
        if response.status_code == 200:
            return response.json()
        else:
            return {
                'error': f'API returned status {response.status_code}',
                'response': response.text
            }
    except Exception as e:
        return {
            'error': f'API request failed: {str(e)}'
        }

def validate_result(filename: str, result: Dict[str, Any], expectation: Dict[str, Any]) -> Dict[str, Any]:
    """Validate analysis result against expectations"""
    validation = {
        'filename': filename,
        'passed': True,
        'issues': [],
        'notes': []
    }
    
    if not result.get('success', True):
        validation['issues'].append(f"Analysis failed: {result.get('error', 'Unknown error')}")
        validation['passed'] = False
        return validation
    
    # Check malicious classification
    is_malicious = result.get('is_malicious', False)
    should_be_malicious = expectation['should_be_malicious']
    
    if is_malicious != should_be_malicious:
        validation['issues'].append(
            f"Malicious classification mismatch: got {is_malicious}, expected {should_be_malicious}"
        )
        validation['passed'] = False
    
    # Check confidence level
    confidence_category = result.get('confidence_category', 'Unknown')
    expected_confidence = expectation['expected_confidence']
    
    # Convert confidence levels to numeric for comparison
    confidence_levels = {'Very Low': 1, 'Low': 2, 'Medium': 3, 'High': 4, 'Very High': 5}
    actual_level = confidence_levels.get(confidence_category, 0)
    expected_level = confidence_levels.get(expected_confidence, 0)
    
    # Allow some tolerance in confidence levels
    if abs(actual_level - expected_level) > 1:
        validation['issues'].append(
            f"Confidence level concern: got {confidence_category}, expected {expected_confidence}"
        )
        # Don't mark as failed for confidence issues, just note them
    
    # Add notes
    validation['notes'].append(expectation['notes'])
    
    return validation

def print_detailed_result(filename: str, result: Dict[str, Any]):
    """Print detailed analysis result"""
    print(f"\n--- {filename} ---")
    
    if not result.get('success', True):
        print(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
        return
    
    print(f"✅ Analysis completed successfully")
    print(f"   Malicious: {result.get('is_malicious', 'Unknown')}")
    print(f"   Threat Score: {result.get('threat_score', 'Unknown')}")
    print(f"   Confidence: {result.get('confidence_level', 'Unknown'):.2f} ({result.get('confidence_category', 'Unknown')})")
    print(f"   Source: {result.get('source', 'Unknown')}")
    print(f"   Hash: {result.get('hash', 'Unknown')[:16]}...")
    
    if result.get('confidence_factors'):
        print(f"   Confidence factors: {', '.join(result['confidence_factors'])}")
    
    print(f"   Analysis: {result.get('rationale', 'No rationale provided')}")

def test_unsupported_format():
    """Test handling of unsupported file format"""
    print("\n=== Testing Unsupported Format ===")
    
    try:
        analyzer = AIAnalyzer()
        result = analyzer.analyze_file('test_files/unsupported_format.txt', 'unsupported_format.txt')
        
        if result.get('success') == False and 'Unsupported file type' in result.get('error', ''):
            print("✅ Unsupported format handled correctly")
            return True
        else:
            print("❌ Unsupported format not handled correctly")
            print(f"   Result: {result}")
            return False
    except Exception as e:
        print(f"❌ Error testing unsupported format: {e}")
        return False

def main():
    """Main validation function"""
    print("Project Sentinel - System Validation")
    print("=" * 50)
    
    # Initialize analyzer
    analyzer = AIAnalyzer()
    
    # Test files directory
    test_dir = 'test_files'
    if not os.path.exists(test_dir):
        print(f"❌ Test directory '{test_dir}' not found. Run create_test_files.py first.")
        return 1
    
    # Get list of supported test files
    supported_files = [f for f in os.listdir(test_dir) if f.endswith(('.pdf', '.docx', '.xlsx'))]
    
    print(f"Testing {len(supported_files)} files...")
    
    results = []
    validations = []
    
    # Test each file
    for filename in supported_files:
        file_path = os.path.join(test_dir, filename)
        
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            continue
        
        print(f"\nTesting: {filename}")
        
        # Analyze file
        result = analyze_file_locally(analyzer, file_path)
        results.append(result)
        
        # Print detailed result
        print_detailed_result(filename, result)
        
        # Validate against expectations
        if filename in TEST_EXPECTATIONS:
            validation = validate_result(filename, result, TEST_EXPECTATIONS[filename])
            validations.append(validation)
            
            if validation['passed']:
                print(f"✅ Validation passed")
            else:
                print(f"❌ Validation issues:")
                for issue in validation['issues']:
                    print(f"   - {issue}")
    
    # Test unsupported format
    unsupported_test_passed = test_unsupported_format()
    
    # Summary
    print("\n" + "=" * 50)
    print("VALIDATION SUMMARY")
    print("=" * 50)
    
    passed_count = sum(1 for v in validations if v['passed'])
    total_count = len(validations)
    
    print(f"Files tested: {total_count}")
    print(f"Validations passed: {passed_count}")
    print(f"Validations failed: {total_count - passed_count}")
    print(f"Unsupported format test: {'✅ PASSED' if unsupported_test_passed else '❌ FAILED'}")
    
    # List any issues
    issues_found = []
    for validation in validations:
        if not validation['passed']:
            issues_found.extend(validation['issues'])
    
    if issues_found:
        print(f"\nIssues found:")
        for issue in issues_found:
            print(f"  - {issue}")
    
    # Overall result
    overall_success = (passed_count == total_count) and unsupported_test_passed
    print(f"\nOverall result: {'✅ PASSED' if overall_success else '❌ FAILED'}")
    
    if overall_success:
        print("\n🎉 All tests passed! The system is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Review the issues above.")
    
    return 0 if overall_success else 1

if __name__ == "__main__":
    exit(main()) 