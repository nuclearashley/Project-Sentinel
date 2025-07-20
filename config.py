#!/usr/bin/env python3
"""
Configuration for Project Sentinel
Handles API keys and configuration settings securely
"""

import os

# API Configuration
class Config:
    """Configuration settings for Project Sentinel"""
    
    # Anthropic (Claude) API Configuration - get from environment only
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
    
    # VirusTotal API Configuration
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '64c677585c0856c000004edf7292f93a6feb8c12a7062f2c400e9a51328d720d')
    
    # Flask Configuration
    SECRET_KEY = 'asdf#FGSgvasgf$5$WGT'
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size
    
    # AI Model Configuration
    AI_MODEL = "claude-3-5-sonnet-20241022"
    AI_MAX_TOKENS = 1000
    AI_RATE_LIMIT_DELAY = 1.0  # seconds between requests
    
    @classmethod
    def get_anthropic_api_key(cls):
        """Get Anthropic API key from environment"""
        return cls.ANTHROPIC_API_KEY
    
    @classmethod
    def get_virustotal_api_key(cls):
        """Get VirusTotal API key with fallback"""
        return cls.VIRUSTOTAL_API_KEY
    
    @classmethod
    def is_ai_enabled(cls):
        """Check if AI features are enabled"""
        return bool(cls.get_anthropic_api_key())
    
    @classmethod
    def print_config_status(cls):
        """Print configuration status"""
        print("🔧 Configuration Status:")
        print(f"   AI Enabled: {'✅' if cls.is_ai_enabled() else '❌'}")
        if cls.is_ai_enabled():
            key = cls.get_anthropic_api_key()
            if key and len(key) > 20:
                print(f"   Anthropic Key: {key[:10]}...{key[-10:]}")
            elif key:
                print(f"   Anthropic Key: {key}")
            else:
                print("   Anthropic Key: Not configured")
        print(f"   VirusTotal: {'✅' if cls.get_virustotal_api_key() else '❌'}")
        print(f"   AI Model: {cls.AI_MODEL}")

# Export configuration instance
config = Config() 