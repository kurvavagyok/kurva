# JADE Ultimate - AI Service
# Multi-LLM integration for security analysis and threat intelligence

import os
import json
import asyncio
import time
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
import structlog
from dataclasses import dataclass

# AI SDK imports
import openai
from openai import OpenAI
import anthropic
from anthropic import Anthropic
from google import genai
from google.genai import types
import requests

logger = structlog.get_logger()

@dataclass
class AIResponse:
    content: str
    model: str
    provider: str
    tokens_used: int
    response_time: float
    confidence: float
    metadata: Dict[str, Any]

class AIService:
    """
    Comprehensive AI service supporting multiple LLM providers
    for security analysis, threat intelligence, and report generation
    """
    
    def __init__(self):
        self.providers = {}
        self.models = {}
        self.initialize_providers()
    
    def initialize_providers(self):
        """Initialize all AI providers"""
        # OpenAI
        if os.environ.get("OPENAI_API_KEY"):
            self.providers['openai'] = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
            self.models['openai'] = {
                'gpt-4o': {'max_tokens': 4000, 'supports_vision': True},
                'gpt-4o-mini': {'max_tokens': 16000, 'supports_vision': True}
            }
            logger.info("OpenAI provider initialized")
        
        # Anthropic
        if os.environ.get("ANTHROPIC_API_KEY"):
            self.providers['anthropic'] = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
            self.models['anthropic'] = {
                'claude-sonnet-4-20250514': {'max_tokens': 8000, 'supports_vision': True}
            }
            logger.info("Anthropic provider initialized")
        
        # Google Gemini
        if os.environ.get("GEMINI_API_KEY"):
            self.providers['google'] = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
            self.models['google'] = {
                'gemini-2.5-flash': {'max_tokens': 8000, 'supports_vision': True},
                'gemini-2.5-pro': {'max_tokens': 32000, 'supports_vision': True}
            }
            logger.info("Google Gemini provider initialized")
    
    async def analyze_vulnerability(self, vulnerability_data: Dict[str, Any], model: str = "gpt-4o") -> AIResponse:
        """
        Analyze vulnerability using AI for enhanced insights
        """
        try:
            prompt = f"""
            Analyze the following security vulnerability and provide comprehensive insights:

            Vulnerability Details:
            - Title: {vulnerability_data.get('title', 'Unknown')}
            - Description: {vulnerability_data.get('description', 'No description')}
            - Severity: {vulnerability_data.get('severity', 'Unknown')}
            - CVE ID: {vulnerability_data.get('cve_id', 'None')}
            - Target: {vulnerability_data.get('target_host', 'Unknown')}:{vulnerability_data.get('target_port', 'Unknown')}
            - Service: {vulnerability_data.get('target_service', 'Unknown')}

            Raw Scanner Output:
            {vulnerability_data.get('raw_output', 'No raw output available')}

            Please provide:
            1. Risk Assessment (1-10 scale with justification)
            2. Business Impact Analysis
            3. Exploitation Likelihood
            4. Detailed Remediation Steps
            5. Prevention Strategies
            6. Related Vulnerabilities to Check
            7. Compliance Impact (GDPR, SOC2, ISO27001)

            Format your response as JSON with the following structure:
            {{
                "risk_score": <1-10>,
                "business_impact": "<detailed analysis>",
                "exploitation_likelihood": "<low/medium/high with reasoning>",
                "remediation_steps": ["step1", "step2", ...],
                "prevention_strategies": ["strategy1", "strategy2", ...],
                "related_vulnerabilities": ["vuln1", "vuln2", ...],
                "compliance_impact": {{"gdpr": "<impact>", "soc2": "<impact>", "iso27001": "<impact>"}},
                "executive_summary": "<summary for executives>",
                "technical_details": "<technical analysis>",
                "confidence_level": <0.0-1.0>
            }}
            """
            
            response = await self._call_ai_model(prompt, model, response_format="json")
            
            # Parse JSON response
            try:
                analysis = json.loads(response.content)
                response.metadata['analysis'] = analysis
                response.confidence = analysis.get('confidence_level', 0.8)
            except json.JSONDecodeError:
                logger.error("Failed to parse AI analysis JSON response")
                response.confidence = 0.5
            
            return response
            
        except Exception as e:
            logger.error("AI vulnerability analysis failed", error=str(e))
            return AIResponse(
                content="Analysis failed",
                model=model,
                provider=self._get_provider_from_model(model),
                tokens_used=0,
                response_time=0.0,
                confidence=0.0,
                metadata={"error": str(e)}
            )
    
    async def generate_scan_report(self, scan_data: Dict[str, Any], report_type: str = "executive") -> AIResponse:
        """
        Generate comprehensive security scan report using AI
        """
        try:
            vulnerabilities = scan_data.get('vulnerabilities', [])
            scan_metadata = scan_data.get('metadata', {})
            
            if report_type == "executive":
                prompt = f"""
                Generate an executive summary report for the following security scan:

                Scan Information:
                - Scan Name: {scan_data.get('name', 'Security Scan')}
                - Target: {scan_data.get('target', 'Unknown')}
                - Scan Type: {scan_data.get('scan_type', 'Unknown')}
                - Duration: {scan_data.get('duration', 'Unknown')} seconds
                - Total Vulnerabilities: {len(vulnerabilities)}

                Vulnerability Summary:
                - Critical: {scan_data.get('critical_vulns', 0)}
                - High: {scan_data.get('high_vulns', 0)}
                - Medium: {scan_data.get('medium_vulns', 0)}
                - Low: {scan_data.get('low_vulns', 0)}

                Top Vulnerabilities:
                {self._format_top_vulnerabilities(vulnerabilities[:10])}

                Create an executive-level report that includes:
                1. Executive Summary (high-level overview)
                2. Risk Assessment (overall security posture)
                3. Key Findings (most critical issues)
                4. Business Impact (potential consequences)
                5. Recommendations (prioritized action items)
                6. Compliance Status (regulatory implications)
                7. Resource Requirements (estimated effort/cost)

                Format as professional executive report in HTML.
                """
            else:  # technical report
                prompt = f"""
                Generate a detailed technical security report for the following scan:

                Scan Information:
                - Scan Name: {scan_data.get('name', 'Security Scan')}
                - Target: {scan_data.get('target', 'Unknown')}
                - Scan Type: {scan_data.get('scan_type', 'Unknown')}
                - Tools Used: {scan_metadata.get('tools_used', [])}
                - Duration: {scan_data.get('duration', 'Unknown')} seconds

                Detailed Vulnerabilities:
                {self._format_all_vulnerabilities(vulnerabilities)}

                Create a comprehensive technical report with:
                1. Methodology (scan approach and tools)
                2. Network Topology (discovered services and ports)
                3. Vulnerability Analysis (detailed findings)
                4. Proof of Concept (exploitation details)
                5. Remediation Guide (step-by-step fixes)
                6. Appendices (raw data and references)

                Format as detailed technical report in HTML.
                """
            
            response = await self._call_ai_model(prompt, "gpt-4o")
            return response
            
        except Exception as e:
            logger.error("AI report generation failed", error=str(e))
            return AIResponse(
                content="Report generation failed",
                model="gpt-4o",
                provider="openai",
                tokens_used=0,
                response_time=0.0,
                confidence=0.0,
                metadata={"error": str(e)}
            )
    
    async def analyze_threat_intelligence(self, indicators: List[str], context: Dict[str, Any]) -> AIResponse:
        """
        Analyze threat intelligence indicators using AI
        """
        try:
            prompt = f"""
            Analyze the following threat intelligence indicators and provide strategic insights:

            Indicators:
            {json.dumps(indicators, indent=2)}

            Context:
            {json.dumps(context, indent=2)}

            Provide comprehensive threat intelligence analysis including:
            1. Threat Actor Attribution (likely groups/campaigns)
            2. Attack Vector Analysis (methods and techniques)
            3. Geographical Analysis (origin and targets)
            4. Timeline Analysis (campaign progression)
            5. Impact Assessment (potential damage)
            6. Mitigation Strategies (defensive measures)
            7. Attribution Confidence (low/medium/high)

            Format response as JSON with structured analysis.
            """
            
            response = await self._call_ai_model(prompt, "claude-sonnet-4-20250514", response_format="json")
            return response
            
        except Exception as e:
            logger.error("AI threat intelligence analysis failed", error=str(e))
            return AIResponse(
                content="Analysis failed",
                model="claude-sonnet-4-20250514",
                provider="anthropic",
                tokens_used=0,
                response_time=0.0,
                confidence=0.0,
                metadata={"error": str(e)}
            )
    
    async def generate_remediation_plan(self, vulnerabilities: List[Dict[str, Any]]) -> AIResponse:
        """
        Generate prioritized remediation plan using AI
        """
        try:
            prompt = f"""
            Create a comprehensive remediation plan for the following vulnerabilities:

            Vulnerabilities:
            {json.dumps(vulnerabilities, indent=2)}

            Generate a prioritized remediation plan with:
            1. Risk-based Prioritization (critical first approach)
            2. Resource Allocation (time and skill requirements)
            3. Implementation Timeline (phased approach)
            4. Dependencies (prerequisite fixes)
            5. Validation Steps (testing procedures)
            6. Rollback Plans (contingency measures)
            7. Success Metrics (completion criteria)

            Format as structured remediation plan in JSON.
            """
            
            response = await self._call_ai_model(prompt, "gemini-2.5-pro", response_format="json")
            return response
            
        except Exception as e:
            logger.error("AI remediation plan generation failed", error=str(e))
            return AIResponse(
                content="Plan generation failed",
                model="gemini-2.5-pro",
                provider="google",
                tokens_used=0,
                response_time=0.0,
                confidence=0.0,
                metadata={"error": str(e)}
            )
    
    async def classify_security_event(self, event_data: Dict[str, Any]) -> AIResponse:
        """
        Classify security events using AI
        """
        try:
            prompt = f"""
            Classify the following security event:

            Event Data:
            {json.dumps(event_data, indent=2)}

            Provide classification with:
            1. Event Type (attack, anomaly, false positive, etc.)
            2. Severity Level (1-10 scale)
            3. Confidence Score (0.0-1.0)
            4. MITRE ATT&CK Mapping
            5. Recommended Response
            6. Escalation Requirements

            Format as JSON classification.
            """
            
            response = await self._call_ai_model(prompt, "gpt-4o", response_format="json")
            return response
            
        except Exception as e:
            logger.error("AI event classification failed", error=str(e))
            return AIResponse(
                content="Classification failed",
                model="gpt-4o",
                provider="openai",
                tokens_used=0,
                response_time=0.0,
                confidence=0.0,
                metadata={"error": str(e)}
            )
    
    async def _call_ai_model(self, prompt: str, model: str, response_format: str = "text") -> AIResponse:
        """
        Call AI model with proper error handling and metrics
        """
        start_time = time.time()
        provider = self._get_provider_from_model(model)
        
        try:
            if provider == "openai":
                response = await self._call_openai(prompt, model, response_format)
            elif provider == "anthropic":
                response = await self._call_anthropic(prompt, model, response_format)
            elif provider == "google":
                response = await self._call_google(prompt, model, response_format)
            else:
                raise ValueError(f"Unsupported AI provider: {provider}")
            
            response_time = time.time() - start_time
            
            return AIResponse(
                content=response['content'],
                model=model,
                provider=provider,
                tokens_used=response.get('tokens_used', 0),
                response_time=response_time,
                confidence=response.get('confidence', 0.8),
                metadata=response.get('metadata', {})
            )
            
        except Exception as e:
            logger.error("AI model call failed", 
                        model=model, 
                        provider=provider, 
                        error=str(e))
            raise
    
    async def _call_openai(self, prompt: str, model: str, response_format: str) -> Dict[str, Any]:
        """Call OpenAI API"""
        client = self.providers['openai']
        
        messages = [{"role": "user", "content": prompt}]
        
        kwargs = {
            "model": model,
            "messages": messages,
            "max_tokens": self.models['openai'][model]['max_tokens'],
            "temperature": 0.1
        }
        
        if response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}
        
        response = client.chat.completions.create(**kwargs)
        
        return {
            'content': response.choices[0].message.content,
            'tokens_used': response.usage.total_tokens,
            'metadata': {'finish_reason': response.choices[0].finish_reason}
        }
    
    async def _call_anthropic(self, prompt: str, model: str, response_format: str) -> Dict[str, Any]:
        """Call Anthropic API"""
        client = self.providers['anthropic']
        
        if response_format == "json":
            prompt = f"{prompt}\n\nPlease respond with valid JSON only."
        
        response = client.messages.create(
            model=model,
            max_tokens=self.models['anthropic'][model]['max_tokens'],
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return {
            'content': response.content[0].text,
            'tokens_used': response.usage.input_tokens + response.usage.output_tokens,
            'metadata': {'stop_reason': response.stop_reason}
        }
    
    async def _call_google(self, prompt: str, model: str, response_format: str) -> Dict[str, Any]:
        """Call Google Gemini API"""
        client = self.providers['google']
        
        if response_format == "json":
            prompt = f"{prompt}\n\nPlease respond with valid JSON only."
        
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=self.models['google'][model]['max_tokens']
            )
        )
        
        return {
            'content': response.text,
            'tokens_used': 0,  # Gemini doesn't provide token usage
            'metadata': {'finish_reason': 'stop'}
        }
    
    def _get_provider_from_model(self, model: str) -> str:
        """Get provider name from model name"""
        if model.startswith('gpt-'):
            return 'openai'
        elif model.startswith('claude-'):
            return 'anthropic'
        elif model.startswith('gemini-'):
            return 'google'
        else:
            return 'unknown'
    
    def _format_top_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format top vulnerabilities for reporting"""
        if not vulnerabilities:
            return "No vulnerabilities found"
        
        formatted = []
        for vuln in vulnerabilities:
            formatted.append(f"- {vuln.get('title', 'Unknown')} ({vuln.get('severity', 'Unknown')})")
        
        return "\n".join(formatted)
    
    def _format_all_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format all vulnerabilities for detailed reporting"""
        if not vulnerabilities:
            return "No vulnerabilities found"
        
        formatted = []
        for vuln in vulnerabilities:
            formatted.append(f"""
            Title: {vuln.get('title', 'Unknown')}
            Severity: {vuln.get('severity', 'Unknown')}
            CVE: {vuln.get('cve_id', 'None')}
            Target: {vuln.get('target_host', 'Unknown')}:{vuln.get('target_port', 'Unknown')}
            Description: {vuln.get('description', 'No description')}
            """)
        
        return "\n".join(formatted)
    
    def get_available_models(self) -> Dict[str, List[str]]:
        """Get list of available AI models"""
        available = {}
        for provider, models in self.models.items():
            if provider in self.providers:
                available[provider] = list(models.keys())
        return available
    
    def get_model_info(self, model: str) -> Dict[str, Any]:
        """Get information about a specific model"""
        provider = self._get_provider_from_model(model)
        if provider in self.models and model in self.models[provider]:
            return self.models[provider][model]
        return {}
