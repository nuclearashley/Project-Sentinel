# Project Sentinel: AI-Enhanced Setup Guide

## Overview

Project Sentinel now includes **AI-powered threat analysis** using Claude API for intelligent threat assessment and natural language explanations. This guide covers setup and configuration.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Install Python dependencies (includes Claude API)
pip install -r requirements.txt
```

### 2. Configure Claude API

You need an Anthropic API key to enable AI-powered analysis:

1. **Get API Key:**
   - Visit [Anthropic Console](https://console.anthropic.com/)
   - Sign up/login and create an API key
   - **Cost:** ~$0.01-0.05 per analysis (very affordable for academic use)

2. **Set Environment Variable:**

   **Option A: Command Line (Temporary)**
   ```bash
   export ANTHROPIC_API_KEY="your_api_key_here"
   python main.py
   ```

   **Option B: Create .env File (Recommended)**
   ```bash
   # Create .env file in project root
   echo "ANTHROPIC_API_KEY=your_api_key_here" > .env
   ```

   **Option C: System Environment (Permanent)**
   ```bash
   # Add to ~/.bashrc or ~/.zshrc
   echo 'export ANTHROPIC_API_KEY="your_api_key_here"' >> ~/.bashrc
   source ~/.bashrc
   ```

### 3. Run Project Sentinel

```bash
python main.py
# Open http://localhost:5001 in your browser
```

## 🤖 AI Features

When properly configured, Project Sentinel provides:

### **Intelligent Threat Assessment**
- AI analyzes rule-based detection results
- Provides expert-level threat categorization (SAFE/LOW/MEDIUM/HIGH/CRITICAL)
- Considers file type and specific attack vectors

### **Natural Language Explanations**
- Detailed security analysis in plain English
- Technical explanations of detected patterns
- Context-aware threat descriptions

### **Enhanced Confidence Scoring**
- AI-powered confidence assessment
- Multi-factor confidence analysis
- Combined rule-based + AI scoring

### **Security Recommendations**
- Actionable security advice
- File handling recommendations
- Risk mitigation strategies

## 📊 AI vs Rule-Based Analysis

| Feature | Rule-Based Only | AI-Enhanced |
|---------|----------------|-------------|
| **Speed** | ~1 second | ~3-5 seconds |
| **Accuracy** | Pattern matching | Expert-level analysis |
| **Explanations** | Template-based | Natural language |
| **Cost** | Free | ~$0.01-0.05 per file |
| **Offline** | ✅ Yes | ❌ Requires internet |

## 🔧 Configuration Options

### Environment Variables

```bash
# Required for AI features
ANTHROPIC_API_KEY=your_api_key_here

# Optional: VirusTotal integration
VIRUSTOTAL_API_KEY=your_vt_key_here
```

### API Configuration

The system uses Claude 3 Sonnet for optimal balance of performance and cost:

- **Model:** `claude-3-sonnet-20240229`
- **Max Tokens:** 1000 per request
- **Rate Limit:** 1 second between requests
- **Estimated Cost:** $0.01-0.05 per analysis

## 🧪 Testing AI Integration

### Test with Sample Files

1. **Test without AI (verify baseline):**
   ```bash
   # Remove API key temporarily
   unset ANTHROPIC_API_KEY
   python main.py
   # Upload test file - should show "AI Analysis (Unavailable)"
   ```

2. **Test with AI:**
   ```bash
   export ANTHROPIC_API_KEY="your_key"
   python main.py
   # Upload test file - should show "🤖 AI Security Analysis" section
   ```

### Expected AI Output

For a malicious PDF with JavaScript:

**Rule-Based Analysis:**
```
PDF analysis completed. Threat score: 0.40. JavaScript patterns found (3 instances)
```

**AI-Enhanced Analysis:**
```
AI Analysis: This PDF contains embedded JavaScript code which is commonly used in malicious PDFs to exploit browser vulnerabilities. The presence of multiple JavaScript patterns, particularly those involving automatic execution triggers, indicates a high likelihood of malicious intent. These scripts could potentially execute arbitrary code, steal credentials, or redirect users to malicious websites. The file should be treated as high-risk and analyzed in a sandboxed environment before any interaction.

AI Threat Assessment: HIGH
```

## 🔍 Troubleshooting

### Common Issues

**1. "AI analysis unavailable" message:**
- Check ANTHROPIC_API_KEY is set: `echo $ANTHROPIC_API_KEY`
- Verify API key is valid in [Anthropic Console](https://console.anthropic.com/)

**2. "Rate limit exceeded" errors:**
- Wait 1-2 seconds between requests
- System includes automatic rate limiting

**3. "API quota exceeded":**
- Check billing in Anthropic Console
- Most academic use stays under $5/month

**4. Slow analysis times:**
- Normal with AI: 3-5 seconds vs 1 second rule-based
- Consider API server latency

### Validation Commands

```bash
# Check if dependencies are installed
python -c "import anthropic; print('✅ Anthropic SDK installed')"

# Test API key (without making requests)
python -c "
import os
key = os.getenv('ANTHROPIC_API_KEY')
if key:
    print(f'✅ API key configured: {key[:8]}...')
else:
    print('❌ API key not set')
"

# Test full integration
python -c "
from src.services.ai_service import AIService
ai = AIService()
print('✅ AI service available' if ai.is_available() else '❌ AI service unavailable')
"
```

## 💰 Cost Management

### For Academic Use

- **Typical usage:** 50-100 analyses = $2-5/month
- **Heavy testing:** 500 analyses = $10-25/month
- **Tip:** Test with rule-based first, then enable AI for final demonstrations

### Cost Optimization

1. **Use hash analysis** for known files (free OSINT lookups)
2. **Batch testing** - plan AI analyses in advance
3. **Local development** - use rule-based mode for code testing
4. **Monitor usage** in Anthropic Console

## 🎓 Academic Benefits

### Why AI Enhancement Matters

1. **Genuine AI Integration:** Real Claude API calls, not simulated
2. **Modern Security Approach:** Combines traditional patterns with AI insights
3. **Practical Demonstration:** Shows real-world AI application in cybersecurity
4. **Publication Ready:** Results suitable for academic papers/presentations

### Demo Script

For presentations, follow this sequence:

1. **Show rule-based analysis** (fast, template responses)
2. **Enable AI enhancement** (show environment variable setup)
3. **Compare results** (template vs natural language)
4. **Highlight AI sections** (threat assessment, recommendations)
5. **Discuss cost/benefit** (accuracy vs speed/cost tradeoffs)

## 🔐 Security Notes

- **API Key Security:** Never commit API keys to git
- **Academic Use:** Anthropic allows academic research use
- **Data Privacy:** Files are analyzed by Claude API (consider sensitive data)
- **Local Analysis:** Rule-based analysis works offline if preferred

## 🆘 Support

If you encounter issues:

1. **Check this guide** for common solutions
2. **Verify API configuration** with validation commands  
3. **Test with simple files** before complex samples
4. **Monitor costs** in Anthropic Console
5. **Fallback option:** System works fully without AI (rule-based mode)

---

**🎯 Success Indicator:** When configured correctly, you'll see "🤖 AI Security Analysis" sections with detailed, natural language threat explanations that go far beyond simple template responses. 