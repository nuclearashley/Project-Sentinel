#!/bin/bash

# Project Sentinel - AI-Enabled Startup Script
# This script checks for API key and starts the application with AI analysis enabled

echo "Project Sentinel - AI-Enabled Startup"
echo "====================================="

# Check if API key is set
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "❌ Error: ANTHROPIC_API_KEY environment variable not set"
    echo "Please set your API key first:"
    echo "   export ANTHROPIC_API_KEY='your_api_key_here'"
    echo "Or run: python setup_api_key.py"
    exit 1
else
    echo "✅ API Key configured: ${ANTHROPIC_API_KEY:0:15}..."
fi

# Check if Python is available
if ! command -v python &> /dev/null; then
    echo "❌ Error: Python not found. Please install Python 3.7+"
    exit 1
fi

# Install dependencies if needed
echo "📦 Checking dependencies..."
pip install -q -r requirements.txt

# Start the application
echo "🚀 Starting Project Sentinel..."
echo "   Open http://localhost:5001 in your browser"
echo "   Press Ctrl+C to stop"
echo "====================================="

python main.py 