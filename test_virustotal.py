#!/usr/bin/env python3
"""
Test script for VirusTotal integration
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src.services.osint_checker import OSINTChecker

def test_virustotal_integration():
    """Test VirusTotal integration with a known hash"""
    
    print("🛡️  Testing VirusTotal Integration")
    print("=" * 50)
    
    # Initialize OSINT checker
    osint_checker = OSINTChecker()
    
    # Test with a known malicious hash (EICAR test file)
    # This is a standard test file that most antivirus engines should detect
    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file MD5
    
    print(f"Testing malicious hash: {test_hash}")
    print("Checking against local OSINT database...")
    
    # Check local database first
    if test_hash in osint_checker.malicious_hashes:
        print("✅ Found in local database")
    else:
        print("❌ Not found in local database")
    
    print("\nChecking against VirusTotal...")
    
    # Check VirusTotal
    is_malicious, source_info, details = osint_checker.check_virustotal(test_hash)
    
    if is_malicious:
        print("✅ VirusTotal detected as malicious")
        print(f"Source: {source_info}")
        if details:
            print(f"Detection ratio: {details.get('detection_ratio', 'N/A')}")
            print(f"Total engines: {details.get('total_engines', 'N/A')}")
            if details.get('malicious_engines'):
                print(f"Detected by: {', '.join(details['malicious_engines'][:3])}...")
    elif source_info:
        print(f"ℹ️  VirusTotal result: {source_info}")
    else:
        print("❌ VirusTotal check failed or returned no result")
    
    print("\n" + "-" * 50)
    
    # Test with a clean hash (Windows calculator)
    clean_hash = "c71d239a91746c1ad638eaad6f3b3178"  # Windows calc.exe MD5
    
    print(f"Testing clean hash: {clean_hash}")
    print("Checking against local OSINT database...")
    
    if clean_hash in osint_checker.malicious_hashes:
        print("❌ Found in local database (false positive)")
    else:
        print("✅ Not found in local database")
    
    print("\nChecking against VirusTotal...")
    
    # Check VirusTotal
    is_malicious, source_info, details = osint_checker.check_virustotal(clean_hash)
    
    if is_malicious:
        print("❌ VirusTotal detected as malicious (unexpected)")
        print(f"Source: {source_info}")
    elif source_info:
        print(f"✅ VirusTotal result: {source_info}")
        if details:
            print(f"Detection ratio: {details.get('detection_ratio', 'N/A')}")
            print(f"Total engines: {details.get('total_engines', 'N/A')}")
            if details.get('reputation', 0) > 0:
                print(f"Reputation score: {details['reputation']}")
    else:
        print("ℹ️  VirusTotal check failed or returned no result")
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    test_virustotal_integration() 