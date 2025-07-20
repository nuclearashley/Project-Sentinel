#!/usr/bin/env python3
"""
Setup script for Project Sentinel API keys
Helps configure Anthropic API key safely without hardcoding in source
"""

import os
import sys

def setup_api_key():
    """Interactive setup for API keys"""
    print("🛡️  Project Sentinel API Key Setup")
    print("=" * 40)
    print()
    
    # Check current status
    current_key = os.getenv('ANTHROPIC_API_KEY')
    if current_key:
        print(f"✅ Current API key found: {current_key[:10]}...")
        choice = input("Do you want to update it? (y/N): ").lower()
        if choice != 'y':
            print("Keeping existing configuration.")
            return
    else:
        print("❌ No ANTHROPIC_API_KEY found in environment")
        print()
    
    print("To get your Anthropic API key:")
    print("1. Visit: https://console.anthropic.com/")
    print("2. Sign up/login and create an API key")
    print("3. Copy the key (starts with 'sk-ant-api03-')")
    print()
    
    # Get API key from user
    api_key = input("Enter your Anthropic API key: ").strip()
    
    if not api_key:
        print("❌ No API key provided. Exiting.")
        return
    
    if not api_key.startswith('sk-ant-api03-'):
        print("⚠️  Warning: API key format seems incorrect (should start with 'sk-ant-api03-')")
        choice = input("Continue anyway? (y/N): ").lower()
        if choice != 'y':
            print("Setup cancelled.")
            return
    
    # Set environment variable for current session
    os.environ['ANTHROPIC_API_KEY'] = api_key
    
    # Show setup options
    print()
    print("✅ API key configured for current session!")
    print()
    print("🔧 To make this permanent, choose one option:")
    print()
    
    print("Option 1: Add to your shell profile (Recommended)")
    shell = os.environ.get('SHELL', '/bin/bash')
    if 'zsh' in shell:
        profile_file = "~/.zshrc"
    else:
        profile_file = "~/.bashrc"
    
    print(f"   Add this line to {profile_file}:")
    print(f"   export ANTHROPIC_API_KEY='{api_key}'")
    print()
    
    print("Option 2: Set for current terminal session only:")
    print(f"   export ANTHROPIC_API_KEY='{api_key}'")
    print()
    
    print("Option 3: Run Project Sentinel with the key:")
    print(f"   ANTHROPIC_API_KEY='{api_key}' python main.py")
    print()
    
    # Test the configuration
    print("🧪 Testing API configuration...")
    try:
        from src.services.ai_service import AIService
        ai_service = AIService()
        if ai_service.is_available():
            print("✅ API key is valid and working!")
        else:
            print("❌ API key validation failed")
    except Exception as e:
        print(f"❌ Error testing API: {str(e)}")
    
    print()
    print("🚀 You can now run Project Sentinel:")
    print("   python main.py")
    print()
    print("💰 Cost estimate: ~$0.02-0.05 per analysis")
    print("   Academic usage typically costs $2-5/month")

def main():
    """Main setup function"""
    try:
        setup_api_key()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
    except Exception as e:
        print(f"\n❌ Setup error: {str(e)}")
        print("\nFor manual setup, set the environment variable:")
        print("export ANTHROPIC_API_KEY='your_key_here'")

if __name__ == "__main__":
    main() 