import os
import json
from typing import Dict, Any, Optional, List
from anthropic import Anthropic
import time

class AIService:
    """
    AI-powered threat analysis service using Claude API
    Provides intelligent threat assessment and natural language explanations
    """
    
    def __init__(self):
        # Initialize Claude client
        self.api_key = os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            print("⚠️  WARNING: ANTHROPIC_API_KEY not found. AI analysis will be disabled.")
            print("   Set your API key: export ANTHROPIC_API_KEY='your_key_here'")
            self.client = None
        else:
            try:
                self.client = Anthropic(api_key=self.api_key)
            except Exception as e:
                print(f"⚠️  WARNING: Failed to initialize Anthropic client: {str(e)}")
                self.client = None
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1.0  # Minimum 1 second between requests
        
        # Model configuration
        self.model = "claude-3-5-sonnet-20241022"  # Use Claude 3.5 Sonnet for latest capabilities
        self.max_tokens = 1000
        
    def _rate_limit(self):
        """Enforce rate limiting between API requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def is_available(self) -> bool:
        """Check if AI service is available (API key configured)"""
        return self.client is not None
    
    def analyze_threat_context(self, 
                             file_type: str, 
                             analysis_results: Dict[str, Any],
                             detected_patterns: List[str]) -> Dict[str, Any]:
        """
        Use Claude AI to analyze threat context and provide intelligent assessment
        
        Args:
            file_type: Type of file (PDF, DOCX, XLSX, EXE)
            analysis_results: Results from rule-based analysis
            detected_patterns: List of detected suspicious patterns
        
        Returns:
            AI-enhanced analysis with intelligent explanations
        """
        if not self.is_available():
            return self._fallback_analysis(analysis_results)
        
        try:
            self._rate_limit()
            
            # Prepare context for Claude
            context = self._prepare_analysis_context(file_type, analysis_results, detected_patterns)
            
            # Create system prompt for security analysis
            system_prompt = """You are a cybersecurity expert analyzing potentially malicious files. Your role is to:

1. Assess the threat level based on detected patterns and file characteristics
2. Provide clear, technical explanations of why findings are concerning
3. Suggest specific security implications and recommendations
4. Use professional cybersecurity terminology
5. Be concise but thorough in your analysis

Focus on practical threat assessment rather than theoretical possibilities. Consider the specific file type and detected patterns in your analysis."""

            # Create user prompt with analysis data
            user_prompt = f"""Analyze this {file_type} file for malware characteristics:

DETECTION SUMMARY:
- File Type: {file_type}
- Threat Score: {analysis_results.get('threat_score', 0):.2f}/1.0
- Is Malicious: {analysis_results.get('is_malicious', False)}
- Confidence: {analysis_results.get('confidence_level', 0):.2f}/1.0

DETECTED PATTERNS:
{self._format_patterns(detected_patterns)}

FILE CHARACTERISTICS:
{self._format_file_features(analysis_results.get('features', {}))}

RULE-BASED ANALYSIS:
{analysis_results.get('rationale', 'No rule-based rationale provided')}

Please provide:
1. **Threat Assessment**: Your expert opinion on the threat level (SAFE/LOW/MEDIUM/HIGH/CRITICAL)
2. **Security Analysis**: Detailed explanation of concerning findings and their implications
3. **Risk Factors**: Specific risks this file poses to systems and users
4. **Recommendations**: Actionable security recommendations for handling this file
5. **Confidence Level**: Your confidence in this assessment (0.0-1.0)

Be specific about why certain patterns are concerning in the context of {file_type} files."""

            # Call Claude API
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            # Parse Claude's response
            ai_analysis = self._parse_ai_response(response.content[0].text)
            
            # Enhance original results with AI insights
            enhanced_results = self._combine_analysis(analysis_results, ai_analysis)
            
            return enhanced_results
            
        except Exception as e:
            print(f"AI analysis error: {str(e)}")
            return self._fallback_analysis(analysis_results)
    
    def generate_detailed_explanation(self, 
                                    file_type: str,
                                    threat_score: float,
                                    detected_patterns: List[str],
                                    features: Dict[str, Any]) -> str:
        """
        Generate detailed natural language explanation of analysis results
        """
        if not self.is_available():
            return self._generate_fallback_explanation(threat_score, detected_patterns)
        
        try:
            self._rate_limit()
            
            system_prompt = """You are a cybersecurity analyst explaining malware analysis results to security professionals. Provide clear, technical explanations that help users understand:

1. What was found and why it's concerning
2. The specific attack vectors or malicious behaviors indicated
3. The potential impact on systems and data
4. Technical context for the detected patterns

Use professional cybersecurity language and be specific about threats."""

            user_prompt = f"""Explain the analysis results for this {file_type} file:

THREAT SCORE: {threat_score:.2f}/1.0
DETECTED PATTERNS: {', '.join(detected_patterns) if detected_patterns else 'None'}
FILE FEATURES: {json.dumps(features, indent=2)}

Provide a detailed explanation (2-3 paragraphs) of:
1. What these findings indicate about the file's security status
2. The specific security concerns raised by the detected patterns
3. The technical implications for systems that might process this file

Be specific about {file_type} security context and avoid generic warnings."""

            response = self.client.messages.create(
                model=self.model,
                max_tokens=600,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            return response.content[0].text.strip()
            
        except Exception as e:
            print(f"AI explanation error: {str(e)}")
            return self._generate_fallback_explanation(threat_score, detected_patterns)
    
    def assess_confidence(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use AI to assess confidence in analysis results
        """
        if not self.is_available():
            return {
                "ai_confidence": analysis_results.get('confidence_level', 0.5),
                "confidence_factors": ["Rule-based analysis only"],
                "confidence_explanation": "AI assessment unavailable - using rule-based confidence only"
            }
        
        try:
            self._rate_limit()
            
            system_prompt = """You are a cybersecurity expert evaluating the reliability of malware analysis results. Assess confidence based on:

1. Strength and specificity of detected patterns
2. Consistency between different indicators
3. Known false positive risks for detected patterns
4. Completeness of analysis data available

Provide confidence assessment from 0.0 (no confidence) to 1.0 (very high confidence)."""

            user_prompt = f"""Assess confidence in this malware analysis:

ANALYSIS RESULTS:
{json.dumps(analysis_results, indent=2)}

Provide:
1. **Confidence Score**: 0.0-1.0 confidence in the analysis accuracy
2. **Confidence Factors**: List of factors that increase or decrease confidence
3. **Reliability Assessment**: Brief explanation of result reliability

Focus on technical accuracy and false positive/negative risks."""

            response = self.client.messages.create(
                model=self.model,
                max_tokens=400,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            # Parse confidence assessment
            ai_response = response.content[0].text
            confidence_data = self._parse_confidence_response(ai_response)
            
            return confidence_data
            
        except Exception as e:
            print(f"AI confidence assessment error: {str(e)}")
            return {
                "ai_confidence": analysis_results.get('confidence_level', 0.5),
                "confidence_factors": ["AI assessment failed"],
                "confidence_explanation": f"AI confidence assessment failed: {str(e)}"
            }
    
    def _prepare_analysis_context(self, file_type: str, results: Dict[str, Any], patterns: List[str]) -> Dict[str, Any]:
        """Prepare analysis context for Claude"""
        return {
            "file_type": file_type,
            "threat_score": results.get('threat_score', 0),
            "is_malicious": results.get('is_malicious', False),
            "confidence": results.get('confidence_level', 0),
            "patterns": patterns,
            "features": results.get('features', {}),
            "rationale": results.get('rationale', '')
        }
    
    def _format_patterns(self, patterns: List[str]) -> str:
        """Format detected patterns for AI analysis"""
        if not patterns:
            return "No suspicious patterns detected"
        return "\n".join([f"- {pattern}" for pattern in patterns])
    
    def _format_file_features(self, features: Dict[str, Any]) -> str:
        """Format file features for AI analysis"""
        if not features:
            return "No file features available"
        
        formatted = []
        for key, value in features.items():
            formatted.append(f"- {key}: {value}")
        return "\n".join(formatted)
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """Parse Claude's structured response"""
        # Extract key information from AI response
        lines = response_text.split('\n')
        
        threat_assessment = "UNKNOWN"
        security_analysis = ""
        risk_factors = ""
        recommendations = ""
        ai_confidence = 0.5
        
        current_section = None
        current_content = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Detect sections
            if "threat assessment" in line.lower() or "**threat assessment**" in line.lower():
                current_section = "threat"
                current_content = []
            elif "security analysis" in line.lower() or "**security analysis**" in line.lower():
                current_section = "security"
                current_content = []
            elif "risk factors" in line.lower() or "**risk factors**" in line.lower():
                current_section = "risk"
                current_content = []
            elif "recommendations" in line.lower() or "**recommendations**" in line.lower():
                current_section = "recommendations"
                current_content = []
            elif "confidence" in line.lower() and ("**confidence" in line.lower() or "confidence level" in line.lower()):
                current_section = "confidence"
                current_content = []
            else:
                # Content line
                if current_section:
                    current_content.append(line)
                    
                    # Save content when switching sections or at end
                    if current_section == "threat" and any(level in line.upper() for level in ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]):
                        for level in ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                            if level in line.upper():
                                threat_assessment = level
                                break
                    elif current_section == "security":
                        security_analysis = " ".join(current_content)
                    elif current_section == "risk":
                        risk_factors = " ".join(current_content)
                    elif current_section == "recommendations":
                        recommendations = " ".join(current_content)
                    elif current_section == "confidence":
                        # Extract confidence number
                        import re
                        confidence_match = re.search(r'([0-9]*\.?[0-9]+)', line)
                        if confidence_match:
                            try:
                                ai_confidence = float(confidence_match.group(1))
                                if ai_confidence > 1.0:
                                    ai_confidence = ai_confidence / 100.0  # Convert percentage
                            except ValueError:
                                pass
        
        return {
            "threat_assessment": threat_assessment,
            "security_analysis": security_analysis.strip(),
            "risk_factors": risk_factors.strip(),
            "recommendations": recommendations.strip(),
            "ai_confidence": ai_confidence
        }
    
    def _parse_confidence_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI confidence assessment response"""
        import re
        
        # Extract confidence score
        confidence_match = re.search(r'([0-9]*\.?[0-9]+)', response_text)
        ai_confidence = 0.5
        if confidence_match:
            try:
                ai_confidence = float(confidence_match.group(1))
                if ai_confidence > 1.0:
                    ai_confidence = ai_confidence / 100.0
            except ValueError:
                pass
        
        # Extract factors (look for bullet points or lists)
        factors = []
        lines = response_text.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('-') or line.startswith('•') or line.startswith('*'):
                factors.append(line[1:].strip())
        
        if not factors:
            factors = ["AI-based confidence assessment"]
        
        return {
            "ai_confidence": ai_confidence,
            "confidence_factors": factors,
            "confidence_explanation": response_text[:200] + "..." if len(response_text) > 200 else response_text
        }
    
    def _combine_analysis(self, original: Dict[str, Any], ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Combine rule-based and AI analysis results"""
        # Create enhanced results
        enhanced = original.copy()
        
        # Update with AI insights
        enhanced['ai_threat_assessment'] = ai_analysis.get('threat_assessment', 'UNKNOWN')
        enhanced['ai_security_analysis'] = ai_analysis.get('security_analysis', '')
        enhanced['ai_risk_factors'] = ai_analysis.get('risk_factors', '')
        enhanced['ai_recommendations'] = ai_analysis.get('recommendations', '')
        enhanced['ai_confidence'] = ai_analysis.get('ai_confidence', 0.5)
        
        # Enhance rationale with AI insights
        original_rationale = enhanced.get('rationale', '')
        ai_analysis_text = ai_analysis.get('security_analysis', '')
        
        if ai_analysis_text:
            enhanced['rationale'] = f"{original_rationale}\n\nAI Analysis: {ai_analysis_text}"
        
        # Update source to indicate AI enhancement
        enhanced['source'] = 'AI-Enhanced Analysis'
        
        # Combine confidence factors
        original_factors = enhanced.get('confidence_factors', [])
        enhanced['confidence_factors'] = original_factors + [f"AI assessment: {ai_analysis.get('threat_assessment', 'Unknown')}"]
        
        return enhanced
    
    def _fallback_analysis(self, original_results: Dict[str, Any]) -> Dict[str, Any]:
        """Provide fallback analysis when AI is unavailable"""
        enhanced = original_results.copy()
        enhanced['ai_threat_assessment'] = 'AI_UNAVAILABLE'
        enhanced['ai_security_analysis'] = 'AI analysis unavailable - API key not configured'
        enhanced['ai_risk_factors'] = 'Unable to assess AI-enhanced risk factors'
        enhanced['ai_recommendations'] = 'Configure ANTHROPIC_API_KEY for AI-powered recommendations'
        enhanced['ai_confidence'] = 0.0
        enhanced['source'] = 'Rule-Based Analysis (AI Unavailable)'
        return enhanced
    
    def _generate_fallback_explanation(self, threat_score: float, patterns: List[str]) -> str:
        """Generate fallback explanation when AI is unavailable"""
        if threat_score > 0.7:
            base = "High threat indicators detected"
        elif threat_score > 0.4:
            base = "Moderate threat indicators detected"
        elif threat_score > 0.1:
            base = "Low-level threat indicators detected"
        else:
            base = "No significant threat indicators detected"
        
        if patterns:
            pattern_text = ", ".join(patterns[:3])  # Limit to first 3
            return f"{base}. Detected patterns include: {pattern_text}. Configure ANTHROPIC_API_KEY for detailed AI analysis."
        else:
            return f"{base}. Configure ANTHROPIC_API_KEY for detailed AI analysis and explanations."

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get AI service usage statistics"""
        return {
            "service_available": self.is_available(),
            "model": self.model if self.is_available() else "N/A",
            "api_configured": self.api_key is not None,
            "rate_limit_interval": self.min_request_interval
        } 