# JADE Ultimate - Threat Intelligence Service
# Comprehensive threat intelligence integration and analysis

import os
import json
import aiohttp
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
from urllib.parse import urlparse
import structlog
from dataclasses import dataclass
import requests
import time

from services.ai_service import AIService
from config import Config

logger = structlog.get_logger()

@dataclass
class ThreatIntelligenceResult:
    indicator: str
    indicator_type: str
    reputation: str  # malicious, suspicious, benign, unknown
    confidence: float
    sources: List[str]
    details: Dict[str, Any]
    last_updated: datetime
    ttl: int  # time to live in seconds

class ThreatIntelligenceService:
    """
    Comprehensive threat intelligence service integrating multiple sources
    """
    
    def __init__(self):
        self.ai_service = AIService()
        self.sources = {
            'virustotal': self._query_virustotal,
            'shodan': self._query_shodan,
            'censys': self._query_censys,
            'otx': self._query_otx,
            'abuseipdb': self._query_abuseipdb
        }
        self.cache = {}  # Simple in-memory cache
        self.rate_limits = {
            'virustotal': {'requests': 4, 'window': 60, 'last_request': 0},
            'shodan': {'requests': 100, 'window': 2592000, 'last_request': 0},  # monthly
            'censys': {'requests': 1000, 'window': 2592000, 'last_request': 0},
            'otx': {'requests': 10000, 'window': 3600, 'last_request': 0},
            'abuseipdb': {'requests': 1000, 'window': 86400, 'last_request': 0}  # daily
        }
    
    async def analyze_indicators(self, indicators: List[str]) -> Dict[str, ThreatIntelligenceResult]:
        """
        Analyze multiple indicators across all threat intelligence sources
        """
        results = {}
        
        for indicator in indicators:
            try:
                result = await self.analyze_indicator(indicator)
                results[indicator] = result
            except Exception as e:
                logger.error("Failed to analyze indicator", indicator=indicator, error=str(e))
                results[indicator] = ThreatIntelligenceResult(
                    indicator=indicator,
                    indicator_type=self._determine_indicator_type(indicator),
                    reputation='unknown',
                    confidence=0.0,
                    sources=[],
                    details={'error': str(e)},
                    last_updated=datetime.now(timezone.utc),
                    ttl=3600
                )
        
        return results
    
    async def analyze_indicator(self, indicator: str) -> ThreatIntelligenceResult:
        """
        Analyze a single indicator across all available sources
        """
        # Check cache first
        cache_key = f"indicator:{indicator}"
        if cache_key in self.cache:
            cached_result = self.cache[cache_key]
            if datetime.now(timezone.utc) - cached_result.last_updated < timedelta(seconds=cached_result.ttl):
                return cached_result
        
        indicator_type = self._determine_indicator_type(indicator)
        
        # Query all available sources
        source_results = {}
        for source_name, query_func in self.sources.items():
            try:
                if self._can_query_source(source_name):
                    result = await query_func(indicator, indicator_type)
                    if result:
                        source_results[source_name] = result
                        self._update_rate_limit(source_name)
            except Exception as e:
                logger.warning(f"Failed to query {source_name}", indicator=indicator, error=str(e))
                continue
        
        # Aggregate results
        aggregated_result = await self._aggregate_results(indicator, indicator_type, source_results)
        
        # Cache result
        self.cache[cache_key] = aggregated_result
        
        return aggregated_result
    
    async def enrich_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich vulnerability data with threat intelligence
        """
        enriched_data = vulnerability_data.copy()
        
        # Extract indicators from vulnerability
        indicators = self._extract_indicators(vulnerability_data)
        
        if indicators:
            # Analyze indicators
            intel_results = await self.analyze_indicators(indicators)
            
            # Add threat intelligence to vulnerability
            enriched_data['threat_intelligence'] = {
                'indicators': intel_results,
                'risk_score': self._calculate_risk_score(intel_results),
                'recommendations': self._generate_recommendations(intel_results)
            }
        
        return enriched_data
    
    async def get_threat_landscape(self, time_range: str = '24h') -> Dict[str, Any]:
        """
        Get threat landscape overview
        """
        try:
            # This would typically aggregate data from multiple sources
            # For now, we'll provide a structured response
            
            threat_landscape = {
                'summary': {
                    'total_indicators': 0,
                    'malicious_indicators': 0,
                    'suspicious_indicators': 0,
                    'top_threats': [],
                    'geographical_distribution': {},
                    'attack_vectors': {}
                },
                'trends': {
                    'malware_families': [],
                    'attack_techniques': [],
                    'targeted_industries': [],
                    'campaign_activity': []
                },
                'recommendations': []
            }
            
            # Use AI to analyze and generate insights
            if self.ai_service:
                ai_analysis = await self.ai_service.analyze_threat_intelligence(
                    [],  # Would pass actual indicators
                    {'time_range': time_range}
                )
                
                if ai_analysis.content:
                    try:
                        ai_insights = json.loads(ai_analysis.content)
                        threat_landscape['ai_insights'] = ai_insights
                    except json.JSONDecodeError:
                        pass
            
            return threat_landscape
            
        except Exception as e:
            logger.error("Failed to get threat landscape", error=str(e))
            return {'error': str(e)}
    
    async def check_ioc_feed(self, feed_url: str) -> List[Dict[str, Any]]:
        """
        Check threat intelligence feed for IOCs
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(feed_url, timeout=30) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Parse different feed formats
                        if feed_url.endswith('.json'):
                            return json.loads(content)
                        elif feed_url.endswith('.csv'):
                            return self._parse_csv_feed(content)
                        else:
                            return self._parse_text_feed(content)
                    else:
                        logger.error("Failed to fetch IOC feed", url=feed_url, status=response.status)
                        return []
        except Exception as e:
            logger.error("Error fetching IOC feed", url=feed_url, error=str(e))
            return []
    
    async def _query_virustotal(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """
        Query VirusTotal API
        """
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if not api_key:
            return None
        
        try:
            headers = {'x-apikey': api_key}
            
            if indicator_type == 'ip':
                url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                params = {'apikey': api_key, 'ip': indicator}
            elif indicator_type == 'domain':
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {'apikey': api_key, 'domain': indicator}
            elif indicator_type == 'url':
                url = f"https://www.virustotal.com/vtapi/v2/url/report"
                params = {'apikey': api_key, 'resource': indicator}
            elif indicator_type == 'file_hash':
                url = f"https://www.virustotal.com/vtapi/v2/file/report"
                params = {'apikey': api_key, 'resource': indicator}
            else:
                return None
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_virustotal_response(data, indicator_type)
                    else:
                        logger.error("VirusTotal API error", status=response.status)
                        return None
        except Exception as e:
            logger.error("VirusTotal query failed", error=str(e))
            return None
    
    async def _query_shodan(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """
        Query Shodan API
        """
        api_key = os.environ.get('SHODAN_API_KEY')
        if not api_key or indicator_type != 'ip':
            return None
        
        try:
            url = f"https://api.shodan.io/shodan/host/{indicator}"
            params = {'key': api_key}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_shodan_response(data)
                    else:
                        logger.error("Shodan API error", status=response.status)
                        return None
        except Exception as e:
            logger.error("Shodan query failed", error=str(e))
            return None
    
    async def _query_censys(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """
        Query Censys API
        """
        api_id = os.environ.get('CENSYS_API_ID')
        api_secret = os.environ.get('CENSYS_API_SECRET')
        
        if not api_id or not api_secret or indicator_type != 'ip':
            return None
        
        try:
            url = f"https://censys.io/api/v1/view/ipv4/{indicator}"
            auth = aiohttp.BasicAuth(api_id, api_secret)
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=auth, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_censys_response(data)
                    else:
                        logger.error("Censys API error", status=response.status)
                        return None
        except Exception as e:
            logger.error("Censys query failed", error=str(e))
            return None
    
    async def _query_otx(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """
        Query AlienVault OTX API
        """
        try:
            # OTX has a free tier, but requires registration
            # This is a placeholder implementation
            base_url = "https://otx.alienvault.com/api/v1/indicators"
            
            if indicator_type == 'ip':
                url = f"{base_url}/IPv4/{indicator}/general"
            elif indicator_type == 'domain':
                url = f"{base_url}/domain/{indicator}/general"
            elif indicator_type == 'url':
                url = f"{base_url}/url/{indicator}/general"
            elif indicator_type == 'file_hash':
                url = f"{base_url}/file/{indicator}/general"
            else:
                return None
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_otx_response(data)
                    else:
                        return None
        except Exception as e:
            logger.error("OTX query failed", error=str(e))
            return None
    
    async def _query_abuseipdb(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """
        Query AbuseIPDB API
        """
        api_key = os.environ.get('ABUSEIPDB_API_KEY')
        if not api_key or indicator_type != 'ip':
            return None
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': indicator,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_abuseipdb_response(data)
                    else:
                        logger.error("AbuseIPDB API error", status=response.status)
                        return None
        except Exception as e:
            logger.error("AbuseIPDB query failed", error=str(e))
            return None
    
    def _determine_indicator_type(self, indicator: str) -> str:
        """
        Determine the type of indicator
        """
        # IP address
        try:
            ipaddress.ip_address(indicator)
            return 'ip'
        except ValueError:
            pass
        
        # Domain
        if '.' in indicator and not indicator.startswith('http'):
            return 'domain'
        
        # URL
        if indicator.startswith(('http://', 'https://')):
            return 'url'
        
        # File hash
        if len(indicator) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return 'file_hash'
        
        return 'unknown'
    
    def _can_query_source(self, source_name: str) -> bool:
        """
        Check if we can query a source based on rate limits
        """
        if source_name not in self.rate_limits:
            return False
        
        rate_limit = self.rate_limits[source_name]
        current_time = time.time()
        
        # Check if enough time has passed since last request
        if current_time - rate_limit['last_request'] < rate_limit['window'] / rate_limit['requests']:
            return False
        
        return True
    
    def _update_rate_limit(self, source_name: str):
        """
        Update rate limit tracking for a source
        """
        if source_name in self.rate_limits:
            self.rate_limits[source_name]['last_request'] = time.time()
    
    async def _aggregate_results(self, indicator: str, indicator_type: str, source_results: Dict[str, Any]) -> ThreatIntelligenceResult:
        """
        Aggregate results from multiple sources
        """
        if not source_results:
            return ThreatIntelligenceResult(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation='unknown',
                confidence=0.0,
                sources=[],
                details={},
                last_updated=datetime.now(timezone.utc),
                ttl=3600
            )
        
        # Calculate aggregate reputation
        reputation_scores = []
        all_details = {}
        sources = list(source_results.keys())
        
        for source, result in source_results.items():
            reputation = result.get('reputation', 'unknown')
            confidence = result.get('confidence', 0.0)
            
            # Convert reputation to numeric score
            reputation_score = {
                'malicious': 1.0,
                'suspicious': 0.7,
                'benign': 0.0,
                'unknown': 0.5
            }.get(reputation, 0.5)
            
            reputation_scores.append((reputation_score, confidence))
            all_details[source] = result
        
        # Weighted average of reputation scores
        if reputation_scores:
            total_weight = sum(confidence for _, confidence in reputation_scores)
            if total_weight > 0:
                weighted_score = sum(score * confidence for score, confidence in reputation_scores) / total_weight
                avg_confidence = total_weight / len(reputation_scores)
            else:
                weighted_score = 0.5
                avg_confidence = 0.0
        else:
            weighted_score = 0.5
            avg_confidence = 0.0
        
        # Convert back to reputation
        if weighted_score >= 0.8:
            final_reputation = 'malicious'
        elif weighted_score >= 0.6:
            final_reputation = 'suspicious'
        elif weighted_score <= 0.2:
            final_reputation = 'benign'
        else:
            final_reputation = 'unknown'
        
        return ThreatIntelligenceResult(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation=final_reputation,
            confidence=avg_confidence,
            sources=sources,
            details=all_details,
            last_updated=datetime.now(timezone.utc),
            ttl=3600  # 1 hour
        )
    
    def _extract_indicators(self, vulnerability_data: Dict[str, Any]) -> List[str]:
        """
        Extract indicators from vulnerability data
        """
        indicators = []
        
        # Extract from target information
        if 'target_host' in vulnerability_data:
            indicators.append(vulnerability_data['target_host'])
        
        # Extract from proof of concept
        if 'proof_of_concept' in vulnerability_data:
            poc = vulnerability_data['proof_of_concept']
            # Simple regex-based extraction (would be more sophisticated in practice)
            import re
            
            # IP addresses
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            indicators.extend(re.findall(ip_pattern, poc))
            
            # Domains
            domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            indicators.extend(re.findall(domain_pattern, poc))
            
            # URLs
            url_pattern = r'https?://[^\s<>"]+'
            indicators.extend(re.findall(url_pattern, poc))
        
        return list(set(indicators))  # Remove duplicates
    
    def _calculate_risk_score(self, intel_results: Dict[str, ThreatIntelligenceResult]) -> float:
        """
        Calculate risk score based on threat intelligence
        """
        if not intel_results:
            return 0.0
        
        risk_scores = []
        for result in intel_results.values():
            reputation_score = {
                'malicious': 1.0,
                'suspicious': 0.7,
                'benign': 0.0,
                'unknown': 0.3
            }.get(result.reputation, 0.3)
            
            risk_scores.append(reputation_score * result.confidence)
        
        return max(risk_scores) if risk_scores else 0.0
    
    def _generate_recommendations(self, intel_results: Dict[str, ThreatIntelligenceResult]) -> List[str]:
        """
        Generate recommendations based on threat intelligence
        """
        recommendations = []
        
        for indicator, result in intel_results.items():
            if result.reputation == 'malicious':
                recommendations.append(f"Immediately block {indicator} - confirmed malicious")
            elif result.reputation == 'suspicious':
                recommendations.append(f"Monitor {indicator} closely - suspicious activity detected")
            elif result.reputation == 'benign':
                recommendations.append(f"{indicator} appears benign but continue monitoring")
        
        return recommendations
    
    def _parse_virustotal_response(self, data: Dict[str, Any], indicator_type: str) -> Dict[str, Any]:
        """
        Parse VirusTotal API response
        """
        if data.get('response_code') != 1:
            return {'reputation': 'unknown', 'confidence': 0.0}
        
        positives = data.get('positives', 0)
        total = data.get('total', 1)
        
        if positives > 0:
            reputation = 'malicious' if positives > total * 0.1 else 'suspicious'
            confidence = min(1.0, positives / total * 2)
        else:
            reputation = 'benign'
            confidence = 0.8
        
        return {
            'reputation': reputation,
            'confidence': confidence,
            'positives': positives,
            'total': total,
            'scan_date': data.get('scan_date'),
            'permalink': data.get('permalink')
        }
    
    def _parse_shodan_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Shodan API response
        """
        return {
            'reputation': 'unknown',
            'confidence': 0.5,
            'country': data.get('country_name'),
            'org': data.get('org'),
            'ports': data.get('ports', []),
            'hostnames': data.get('hostnames', []),
            'services': data.get('data', [])
        }
    
    def _parse_censys_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Censys API response
        """
        return {
            'reputation': 'unknown',
            'confidence': 0.5,
            'location': data.get('location', {}),
            'protocols': data.get('protocols', []),
            'services': data.get('services', {})
        }
    
    def _parse_otx_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse OTX API response
        """
        pulse_count = data.get('pulse_info', {}).get('count', 0)
        
        if pulse_count > 0:
            reputation = 'malicious' if pulse_count > 5 else 'suspicious'
            confidence = min(1.0, pulse_count / 10)
        else:
            reputation = 'benign'
            confidence = 0.6
        
        return {
            'reputation': reputation,
            'confidence': confidence,
            'pulse_count': pulse_count,
            'pulse_info': data.get('pulse_info', {})
        }
    
    def _parse_abuseipdb_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse AbuseIPDB API response
        """
        abuse_confidence = data.get('data', {}).get('abuseConfidencePercentage', 0)
        
        if abuse_confidence > 75:
            reputation = 'malicious'
            confidence = 0.9
        elif abuse_confidence > 25:
            reputation = 'suspicious'
            confidence = 0.7
        else:
            reputation = 'benign'
            confidence = 0.6
        
        return {
            'reputation': reputation,
            'confidence': confidence,
            'abuse_confidence': abuse_confidence,
            'country': data.get('data', {}).get('countryCode'),
            'usage_type': data.get('data', {}).get('usageType')
        }
    
    def _parse_csv_feed(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse CSV threat intelligence feed
        """
        indicators = []
        lines = content.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split(',')
            if len(parts) >= 2:
                indicators.append({
                    'indicator': parts[0].strip(),
                    'type': parts[1].strip(),
                    'confidence': float(parts[2]) if len(parts) > 2 else 0.8
                })
        
        return indicators
    
    def _parse_text_feed(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse text threat intelligence feed
        """
        indicators = []
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                indicator_type = self._determine_indicator_type(line)
                indicators.append({
                    'indicator': line,
                    'type': indicator_type,
                    'confidence': 0.8
                })
        
        return indicators

