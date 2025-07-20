#!/usr/bin/env python3
"""
Test AI Integration for Project Sentinel
Tests Claude API integration and AI-enhanced analysis
"""

import os
import sys
import tempfile
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_ai_service():
    """Test AI service initialization and availability"""
    print("🤖 Testing AI Service...")
    
    try:
        from services.ai_service import AIService
        ai_service = AIService()
        
        print(f"   API Key configured: {'✅' if ai_service.is_available() else '❌'}")
        
        if ai_service.is_available():
            print(f"   Model: {ai_service.model}")
            print(f"   Max tokens: {ai_service.max_tokens}")
            return True
        else:
            print("   ⚠️  Set ANTHROPIC_API_KEY to enable AI features")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False

def test_ai_analyzer():
    """Test AI analyzer integration"""
    print("\n🔍 Testing AI Analyzer Integration...")
    
    try:
        from services.ai_analyzer import AIAnalyzer
        analyzer = AIAnalyzer()
        
        print(f"   AI service available: {'✅' if analyzer.ai_service.is_available() else '❌'}")
        print(f"   Supported formats: {list(analyzer.supported_extensions.keys())}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False

def create_test_pdf():
    """Create a simple test PDF with suspicious content"""
    test_content = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Action
/S /JavaScript
/JS (app.alert("This is a test JavaScript in PDF");)
>>
endobj

4 0 obj
<<
/Type /Page
/Parent 2 0 R
/Contents 5 0 R
>>
endobj

5 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Test PDF) Tj
ET
endstream
endobj

xref
0 6
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000136 00000 n 
0000000229 00000 n 
0000000289 00000 n 
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
381
%%EOF"""
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
        f.write(test_content)
        return f.name

def test_file_analysis():
    """Test complete file analysis with AI enhancement"""
    print("\n📄 Testing File Analysis with AI...")
    
    try:
        from services.ai_analyzer import AIAnalyzer
        analyzer = AIAnalyzer()
        
        # Create test PDF
        test_file = create_test_pdf()
        print(f"   Created test PDF: {test_file}")
        
        # Analyze file
        print("   🔍 Analyzing file...")
        start_time = time.time()
        result = analyzer.analyze_file(test_file, "test_malicious.pdf")
        analysis_time = time.time() - start_time
        
        # Clean up
        os.unlink(test_file)
        
        print(f"   Analysis completed in {analysis_time:.2f} seconds")
        
        if result.get('success'):
            print(f"   ✅ Analysis successful")
            print(f"   Threat Score: {result.get('threat_score', 0):.2f}")
            print(f"   Is Malicious: {result.get('is_malicious', False)}")
            print(f"   Confidence: {result.get('confidence_level', 0):.2f}")
            print(f"   Source: {result.get('source', 'Unknown')}")
            
            # Check AI enhancement
            if result.get('ai_threat_assessment'):
                print(f"   🤖 AI Threat Assessment: {result['ai_threat_assessment']}")
                print(f"   🤖 AI Confidence: {result.get('ai_confidence', 0):.2f}")
                if result.get('ai_security_analysis'):
                    analysis_preview = result['ai_security_analysis'][:100] + "..." if len(result['ai_security_analysis']) > 100 else result['ai_security_analysis']
                    print(f"   🤖 AI Analysis Preview: {analysis_preview}")
                return True
            else:
                print("   ⚠️  No AI enhancement (API key needed)")
                return False
        else:
            print(f"   ❌ Analysis failed: {result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False

def test_pattern_extraction():
    """Test pattern extraction for AI analysis"""
    print("\n🔍 Testing Pattern Extraction...")
    
    try:
        from services.ai_analyzer import AIAnalyzer
        analyzer = AIAnalyzer()
        
        # Mock analysis result
        mock_result = {
            'rationale': 'PDF analysis completed. Threat score: 0.40. JavaScript patterns found (3 instances); Suspicious PDF objects found (2 instances)',
            'features': {
                'found_patterns': ['JavaScript pattern', 'OpenAction trigger', 'Auto-execute macro'],
                'suspicious_apis': 2,
                'is_packed': True,
                'suspicious_patterns': 5
            }
        }
        
        patterns = analyzer._extract_patterns_from_analysis(mock_result)
        print(f"   Extracted patterns: {len(patterns)}")
        for i, pattern in enumerate(patterns[:5], 1):  # Show first 5
            print(f"   {i}. {pattern}")
        
        return len(patterns) > 0
        
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False

def test_cost_estimation():
    """Estimate API costs for typical usage"""
    print("\n💰 Cost Estimation...")
    
    # Rough estimates based on Claude pricing
    cost_per_analysis = 0.025  # Conservative estimate
    
    scenarios = [
        ("Single demo", 1, cost_per_analysis * 1),
        ("Class demonstration", 10, cost_per_analysis * 10),
        ("Development testing", 50, cost_per_analysis * 50),
        ("Heavy evaluation", 200, cost_per_analysis * 200),
    ]
    
    for scenario, count, cost in scenarios:
        print(f"   {scenario}: {count} analyses ≈ ${cost:.2f}")
    
    print("   💡 Tip: Use rule-based mode for development, AI for demos")
    return True

def main():
    """Run all tests"""
    print("🛡️  Project Sentinel - AI Integration Test")
    print("=" * 50)
    
    tests = [
        ("AI Service Initialization", test_ai_service),
        ("AI Analyzer Integration", test_ai_analyzer),
        ("Pattern Extraction", test_pattern_extraction),
        ("File Analysis (with AI)", test_file_analysis),
        ("Cost Estimation", test_cost_estimation),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print()
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"   ❌ Test failed with exception: {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status} {test_name}")
        if result:
            passed += 1
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! AI integration is working correctly.")
    elif passed >= total - 1:
        print("⚠️  Most tests passed. Check failed tests above.")
    else:
        print("❌ Multiple tests failed. Check configuration and API setup.")
    
    print("\n💡 Next steps:")
    if os.getenv('ANTHROPIC_API_KEY'):
        print("   • AI is configured - run 'python main.py' to start the server")
        print("   • Upload test files to see AI-enhanced analysis")
    else:
        print("   • Set ANTHROPIC_API_KEY to enable full AI features")
        print("   • See AI_SETUP.md for detailed configuration instructions")

if __name__ == "__main__":
    main() 