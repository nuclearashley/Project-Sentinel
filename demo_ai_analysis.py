#!/usr/bin/env python3
"""
Demo: AI-Enhanced Analysis
Shows the difference between rule-based and AI-enhanced malware analysis
"""

import os
import sys
import tempfile

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def create_malicious_pdf():
    """Create a test PDF with suspicious JavaScript"""
    content = b"""%PDF-1.4
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
/JS (app.alert("Malicious JavaScript executed!");
     app.launchURL("http://malicious-site.com");
     this.print({bUI:false,bSilent:true});)
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
/Length 100
>>
stream
BT
/F1 12 Tf
100 700 Td
(Suspicious Document - Do Not Open) Tj
ET
endstream
endobj

xref
0 6
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000136 00000 n 
0000000350 00000 n 
0000000410 00000 n 
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
559
%%EOF"""
    
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
        f.write(content)
        return f.name

def demo_analysis():
    """Demonstrate AI-enhanced vs rule-based analysis"""
    print("🛡️  PROJECT SENTINEL: AI-Enhanced Malware Analysis Demo")
    print("=" * 60)
    
    from services.ai_analyzer import AIAnalyzer
    
    # Create test file
    test_file = create_malicious_pdf()
    print(f"\n📄 Created test PDF with suspicious JavaScript: {os.path.basename(test_file)}")
    
    # Initialize analyzer
    analyzer = AIAnalyzer()
    
    print(f"\n🤖 AI Service Status: {'✅ Available' if analyzer.ai_service.is_available() else '❌ Unavailable'}")
    
    if analyzer.ai_service.is_available():
        print(f"   Model: {analyzer.ai_service.model}")
        print(f"   API Key: {analyzer.ai_service.api_key[:10]}...")
    
    print("\n🔍 Analyzing File...")
    print("-" * 40)
    
    # Perform analysis
    result = analyzer.analyze_file(test_file, "suspicious_document.pdf")
    
    # Clean up
    os.unlink(test_file)
    
    if result.get('success'):
        print(f"\n📊 ANALYSIS RESULTS")
        print("=" * 30)
        print(f"File: {result['filename']}")
        print(f"Hash: {result['hash'][:16]}...")
        print(f"Threat Score: {result['threat_score']:.2f}/1.0")
        print(f"Is Malicious: {result['is_malicious']}")
        print(f"Confidence: {result['confidence_level']:.2f} ({result['confidence_category']})")
        print(f"Source: {result['source']}")
        
        print(f"\n📝 RULE-BASED RATIONALE:")
        print("-" * 30)
        rule_rationale = result['rationale'].split('\n\nAI Analysis:')[0] if '\n\nAI Analysis:' in result['rationale'] else result['rationale']
        print(rule_rationale)
        
        if result.get('ai_security_analysis') and 'API key not configured' not in result['ai_security_analysis']:
            print(f"\n🤖 AI-ENHANCED ANALYSIS:")
            print("-" * 30)
            print(f"AI Threat Assessment: {result.get('ai_threat_assessment', 'N/A')}")
            print(f"AI Confidence: {result.get('ai_confidence', 0):.2f}")
            
            print(f"\n🔍 AI Security Analysis:")
            print(result['ai_security_analysis'])
            
            if result.get('ai_risk_factors'):
                print(f"\n⚠️  Risk Factors:")
                print(result['ai_risk_factors'])
            
            if result.get('ai_recommendations'):
                print(f"\n💡 AI Recommendations:")
                print(result['ai_recommendations'])
                
            print(f"\n🆚 COMPARISON:")
            print("-" * 30)
            print("Rule-Based: Template-driven pattern matching")
            print("AI-Enhanced: Natural language security analysis")
            print("Combined: Rule accuracy + AI explanation depth")
        else:
            print(f"\n⚠️  AI Analysis: Not available")
            print("Set ANTHROPIC_API_KEY to see AI-enhanced explanations")
        
        print(f"\n🎯 CONFIDENCE FACTORS:")
        print("-" * 30)
        for i, factor in enumerate(result['confidence_factors'], 1):
            print(f"{i}. {factor}")
        
        if result.get('features'):
            print(f"\n🔧 TECHNICAL DETAILS:")
            print("-" * 30)
            for key, value in result['features'].items():
                print(f"  {key}: {value}")
    
    else:
        print(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
    
    print(f"\n💰 API Usage Note:")
    print("This analysis cost approximately $0.02-0.05 using Claude API")
    print("Academic usage typically costs $2-5/month for regular testing")

if __name__ == "__main__":
    demo_analysis() 