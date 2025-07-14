# Applying the requested changes to update metadata references and assignments within the scanner service.
# JADE Ultimate - Scanner Service
# Comprehensive security scanning service with multiple tools

import os
import subprocess
import json
import asyncio
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
import ipaddress
import socket
import ssl
import requests
from urllib.parse import urlparse, urljoin
import structlog
from dataclasses import dataclass
import nmap
import threading
import time

from models import Scan, Vulnerability, VulnerabilitySeverity, ScanStatus
from app import db
from utils.security import validate_target, sanitize_command
from services.ai_service import AIService

logger = structlog.get_logger()

@dataclass
class ScanResult:
    target: str
    scan_type: str
    vulnerabilities: List[Dict[str, Any]]
    scan_metadata: Dict[str, Any]
    raw_output: str
    error: Optional[str] = None

class ScannerService:
    """
    Comprehensive security scanning service supporting multiple tools
    """

    def __init__(self):
        self.ai_service = AIService()
        self.scanner_tools = {
            'nmap': self._run_nmap_scan,
            'web_scan': self._run_web_scan,
            'ssl_scan': self._run_ssl_scan,
            'port_scan': self._run_port_scan,
            'vulnerability_scan': self._run_vulnerability_scan
        }

    async def execute_scan(self, scan_id: int) -> ScanResult:
        """
        Execute a security scan based on scan configuration
        """
        scan = Scan.query.get(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        try:
            # Update scan status
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            db.session.commit()

            logger.info("Starting scan", scan_id=scan.id, target=scan.target, scan_type=scan.scan_type)

            # Validate target
            if not validate_target(scan.target, scan.scan_type):
                raise ValueError(f"Invalid target: {scan.target}")

            # Execute scan based on type
            if scan.scan_type == 'network':
                result = await self._run_network_scan(scan)
            elif scan.scan_type == 'web':
                result = await self._run_web_scan(scan)
            elif scan.scan_type == 'ssl':
                result = await self._run_ssl_scan(scan)
            elif scan.scan_type == 'infrastructure':
                result = await self._run_infrastructure_scan(scan)
            else:
                raise ValueError(f"Unsupported scan type: {scan.scan_type}")

            # Process results and create vulnerabilities
            await self._process_scan_results(scan, result)

            # Update scan completion
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.duration = int((scan.completed_at - scan.started_at).total_seconds())
            scan.scan_metadata = result.scan_metadata

            db.session.commit()

            logger.info("Scan completed", scan_id=scan.id, duration=scan.duration)
            return result

        except Exception as e:
            # Update scan failure
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration = int((scan.completed_at - scan.started_at).total_seconds())

            db.session.commit()

            logger.error("Scan failed", scan_id=scan.id, error=str(e))
            raise

    async def _run_network_scan(self, scan: Scan) -> ScanResult:
        """Run comprehensive network scan"""
        try:
            nm = nmap.PortScanner()

            # Parse scan options
            options = scan.scan_options or {}
            scan_args = self._build_nmap_args(options)

            # Execute nmap scan
            result = nm.scan(scan.target, arguments=scan_args)

            vulnerabilities = []
            scan_metadata = {
                'hosts_scanned': len(nm.all_hosts()),
                'hosts_up': 0,
                'total_ports': 0,
                'open_ports': 0,
                'services_detected': [],
                'os_detection': {}
            }

            # Process scan results
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    scan_metadata['hosts_up'] += 1

                    # Process ports
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        scan_metadata['total_ports'] += len(ports)

                        for port in ports:
                            port_info = nm[host][proto][port]

                            if port_info['state'] == 'open':
                                scan_metadata['open_ports'] += 1

                                # Check for vulnerabilities
                                vulns = await self._analyze_port_service(
                                    host, port, port_info, scan.target
                                )
                                vulnerabilities.extend(vulns)

                                # Track services
                                service_info = {
                                    'host': host,
                                    'port': port,
                                    'protocol': proto,
                                    'service': port_info.get('name', 'unknown'),
                                    'version': port_info.get('version', 'unknown'),
                                    'product': port_info.get('product', 'unknown')
                                }
                                scan_metadata['services_detected'].append(service_info)

                    # OS detection
                    if 'osmatch' in nm[host]:
                        scan_metadata['os_detection'][host] = nm[host]['osmatch']

            return ScanResult(
                target=scan.target,
                scan_type=scan.scan_type,
                vulnerabilities=vulnerabilities,
                scan_metadata=scan_metadata,
                raw_output=json.dumps(result, indent=2)
            )

        except Exception as e:
            logger.error("Network scan failed", error=str(e))
            raise

    async def _run_web_scan(self, scan: Scan) -> ScanResult:
        """Run comprehensive web application scan"""
        try:
            vulnerabilities = []
            scan_metadata = {
                'response_codes': {},
                'technologies': [],
                'headers': {},
                'cookies': [],
                'forms': [],
                'links': [],
                'directories': []
            }

            # Basic web reconnaissance
            url = scan.target
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"

            # HTTP header analysis
            try:
                response = requests.get(url, timeout=30, allow_redirects=True)
                scan_metadata['response_codes'][url] = response.status_code
                scan_metadata['headers'] = dict(response.headers)

                # Check for security headers
                security_headers = [
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'X-XSS-Protection',
                    'Strict-Transport-Security',
                    'Content-Security-Policy',
                    'Referrer-Policy'
                ]

                for header in security_headers:
                    if header not in response.headers:
                        vulnerabilities.append({
                            'title': f'Missing Security Header: {header}',
                            'description': f'The {header} security header is missing',
                            'severity': 'medium',
                            'category': 'security_headers',
                            'target_host': urlparse(url).hostname,
                            'target_port': 80 if url.startswith('http://') else 443,
                            'proof_of_concept': f'Header {header} not found in response',
                            'recommendation': f'Add {header} header to improve security'
                        })

                # Check for dangerous headers
                dangerous_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
                for header in dangerous_headers:
                    if header in response.headers:
                        vulnerabilities.append({
                            'title': f'Information Disclosure: {header}',
                            'description': f'The {header} header reveals server information',
                            'severity': 'low',
                            'category': 'information_disclosure',
                            'target_host': urlparse(url).hostname,
                            'target_port': 80 if url.startswith('http://') else 443,
                            'proof_of_concept': f'{header}: {response.headers[header]}',
                            'recommendation': f'Remove or obfuscate {header} header'
                        })

                # Directory brute force
                directories = await self._brute_force_directories(url)
                scan_metadata['directories'] = directories

                # Check for common vulnerabilities
                await self._check_common_web_vulns(url, vulnerabilities)

            except Exception as e:
                logger.error("Web scan request failed", url=url, error=str(e))
                vulnerabilities.append({
                    'title': 'Web Service Unreachable',
                    'description': f'Failed to connect to {url}: {str(e)}',
                    'severity': 'high',
                    'category': 'availability',
                    'target_host': urlparse(url).hostname,
                    'proof_of_concept': f'Connection error: {str(e)}',
                    'recommendation': 'Verify service is running and accessible'
                })

            return ScanResult(
                target=scan.target,
                scan_type=scan.scan_type,
                vulnerabilities=vulnerabilities,
                scan_metadata=scan_metadata,
                raw_output=json.dumps(scan_metadata, indent=2)
            )

        except Exception as e:
            logger.error("Web scan failed", error=str(e))
            raise

    async def _run_ssl_scan(self, scan: Scan) -> ScanResult:
        """Run SSL/TLS security scan"""
        try:
            vulnerabilities = []
            scan_metadata = {
                'certificate_info': {},
                'cipher_suites': [],
                'protocol_versions': [],
                'vulnerabilities': []
            }

            # Parse target
            if ':' in scan.target:
                host, port = scan.target.split(':')
                port = int(port)
            else:
                host = scan.target
                port = 443

            # SSL/TLS analysis
            try:
                # Get certificate info
                cert_info = self._get_ssl_certificate_info(host, port)
                scan_metadata['certificate_info'] = cert_info

                # Check certificate validity
                if cert_info.get('expired', False):
                    vulnerabilities.append({
                        'title': 'SSL Certificate Expired',
                        'description': 'The SSL certificate has expired',
                        'severity': 'high',
                        'category': 'ssl_tls',
                        'target_host': host,
                        'target_port': port,
                        'proof_of_concept': f'Certificate expired on {cert_info.get("not_after")}',
                        'recommendation': 'Renew SSL certificate immediately'
                    })

                # Check certificate chain
                if cert_info.get('self_signed', False):
                    vulnerabilities.append({
                        'title': 'Self-Signed SSL Certificate',
                        'description': 'The SSL certificate is self-signed',
                        'severity': 'medium',
                        'category': 'ssl_tls',
                        'target_host': host,
                        'target_port': port,
                        'proof_of_concept': 'Certificate is self-signed',
                        'recommendation': 'Use a certificate from a trusted CA'
                    })

                # Check for weak cipher suites
                weak_ciphers = await self._check_weak_ciphers(host, port)
                if weak_ciphers:
                    vulnerabilities.append({
                        'title': 'Weak SSL Cipher Suites',
                        'description': 'Weak cipher suites are enabled',
                        'severity': 'medium',
                        'category': 'ssl_tls',
                        'target_host': host,
                        'target_port': port,
                        'proof_of_concept': f'Weak ciphers: {", ".join(weak_ciphers)}',
                        'recommendation': 'Disable weak cipher suites'
                    })

                # Check SSL/TLS versions
                ssl_versions = await self._check_ssl_versions(host, port)
                scan_metadata['protocol_versions'] = ssl_versions

                # Check for deprecated protocols
                deprecated_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
                for version in ssl_versions:
                    if version in deprecated_protocols:
                        vulnerabilities.append({
                            'title': f'Deprecated SSL/TLS Protocol: {version}',
                            'description': f'The deprecated {version} protocol is enabled',
                            'severity': 'high' if version in ['SSLv2', 'SSLv3'] else 'medium',
                            'category': 'ssl_tls',
                            'target_host': host,
                            'target_port': port,
                            'proof_of_concept': f'{version} protocol is supported',
                            'recommendation': f'Disable {version} protocol'
                        })

            except Exception as e:
                logger.error("SSL scan failed", host=host, port=port, error=str(e))
                vulnerabilities.append({
                    'title': 'SSL/TLS Service Unreachable',
                    'description': f'Failed to connect to SSL service: {str(e)}',
                    'severity': 'high',
                    'category': 'availability',
                    'target_host': host,
                    'target_port': port,
                    'proof_of_concept': f'Connection error: {str(e)}',
                    'recommendation': 'Verify SSL service is running and accessible'
                })

            return ScanResult(
                target=scan.target,
                scan_type=scan.scan_type,
                vulnerabilities=vulnerabilities,
                scan_metadata=scan_metadata,
                raw_output=json.dumps(scan_metadata, indent=2)
            )

        except Exception as e:
            logger.error("SSL scan failed", error=str(e))
            raise

    async def _run_infrastructure_scan(self, scan: Scan) -> ScanResult:
        """Run infrastructure security scan"""
        try:
            vulnerabilities = []
            scan_metadata = {
                'network_info': {},
                'services': [],
                'configurations': {},
                'security_issues': []
            }

            # Network infrastructure analysis
            target_ip = self._resolve_target(scan.target)
            if target_ip:
                scan_metadata['network_info']['ip'] = target_ip
                scan_metadata['network_info']['hostname'] = scan.target

                # Check for common infrastructure vulnerabilities
                await self._check_infrastructure_vulns(target_ip, vulnerabilities)

                # Service enumeration
                services = await self._enumerate_services(target_ip)
                scan_metadata['services'] = services

                # Configuration analysis
                config_issues = await self._analyze_configurations(target_ip, services)
                vulnerabilities.extend(config_issues)

            return ScanResult(
                target=scan.target,
                scan_type=scan.scan_type,
                vulnerabilities=vulnerabilities,
                scan_metadata=scan_metadata,
                raw_output=json.dumps(scan_metadata, indent=2)
            )

        except Exception as e:
            logger.error("Infrastructure scan failed", error=str(e))
            raise

    async def _analyze_port_service(self, host: str, port: int, port_info: Dict, target: str) -> List[Dict]:
        """Analyze a specific port/service for vulnerabilities"""
        vulnerabilities = []

        service = port_info.get('name', 'unknown')
        version = port_info.get('version', 'unknown')
        product = port_info.get('product', 'unknown')

        # Check for known vulnerable services
        if service == 'ssh' and version != 'unknown':
            if 'OpenSSH' in product and version:
                # Check for known OpenSSH vulnerabilities
                if self._is_vulnerable_openssh_version(version):
                    vulnerabilities.append({
                        'title': f'Vulnerable OpenSSH Version: {version}',
                        'description': f'OpenSSH version {version} has known vulnerabilities',
                        'severity': 'high',
                        'category': 'vulnerable_service',
                        'target_host': host,
                        'target_port': port,
                        'target_service': service,
                        'proof_of_concept': f'OpenSSH {version} detected',
                        'recommendation': 'Update OpenSSH to latest version'
                    })

        # Check for default/weak authentication
        if service in ['ftp', 'telnet', 'ssh', 'mysql', 'postgresql']:
            vulnerabilities.append({
                'title': f'Potentially Insecure Service: {service}',
                'description': f'{service} service is exposed and may use weak authentication',
                'severity': 'medium',
                'category': 'exposed_service',
                'target_host': host,
                'target_port': port,
                'target_service': service,
                'proof_of_concept': f'{service} service running on port {port}',
                'recommendation': f'Secure {service} service with strong authentication and access controls'
            })

        # Check for unencrypted services
        unencrypted_services = ['http', 'ftp', 'telnet', 'pop3', 'imap', 'smtp']
        if service in unencrypted_services:
            vulnerabilities.append({
                'title': f'Unencrypted Service: {service}',
                'description': f'{service} service transmits data in cleartext',
                'severity': 'medium',
                'category': 'encryption',
                'target_host': host,
                'target_port': port,
                'target_service': service,
                'proof_of_concept': f'{service} service on port {port} is unencrypted',
                'recommendation': f'Use encrypted version of {service} (HTTPS, FTPS, SSH, etc.)'
            })

        return vulnerabilities

    async def _brute_force_directories(self, base_url: str) -> List[str]:
        """Brute force common directories"""
        common_dirs = [
            'admin', 'administrator', 'login', 'panel', 'control',
            'backup', 'backups', 'config', 'configuration', 'test',
            'tmp', 'temp', 'uploads', 'files', 'images', 'docs',
            'api', 'v1', 'v2', 'swagger', 'documentation'
        ]

        found_dirs = []

        for directory in common_dirs:
            try:
                url = urljoin(base_url, directory)
                response = requests.get(url, timeout=5, allow_redirects=False)

                if response.status_code in [200, 301, 302, 403]:
                    found_dirs.append({
                        'path': directory,
                        'status_code': response.status_code,
                        'url': url
                    })
            except:
                continue

        return found_dirs

    async def _check_common_web_vulns(self, url: str, vulnerabilities: List[Dict]):
        """Check for common web vulnerabilities"""
        # Check for SQL injection in parameters
        # This is a basic example - real implementation would be more comprehensive
        try:
            # Test for basic SQL injection
            sql_payloads = ["'", "1'or'1'='1", "'; DROP TABLE users; --"]

            for payload in sql_payloads:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=10)

                # Look for SQL error messages
                sql_errors = [
                    'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
                    'PostgreSQL query failed', 'sqlite3.OperationalError'
                ]

                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        vulnerabilities.append({
                            'title': 'SQL Injection Vulnerability',
                            'description': 'Application may be vulnerable to SQL injection',
                            'severity': 'high',
                            'category': 'injection',
                            'target_host': urlparse(url).hostname,
                            'target_port': 80 if url.startswith('http://') else 443,
                            'target_path': urlparse(url).path,
                            'proof_of_concept': f'SQL error triggered with payload: {payload}',
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        break
        except:
            pass

    def _get_ssl_certificate_info(self, host: str, port: int) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    # Parse certificate dates
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': not_before.isoformat(),
                        'not_after': not_after.isoformat(),
                        'expired': not_after < datetime.now(),
                        'self_signed': cert['issuer'] == cert['subject'],
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            logger.error("Failed to get SSL certificate info", host=host, port=port, error=str(e))
            return {}

    async def _check_weak_ciphers(self, host: str, port: int) -> List[str]:
        """Check for weak cipher suites"""
        # This is a simplified implementation
        # Real implementation would use tools like sslyze or testssl.sh
        weak_ciphers = []

        try:
            # Connect and get cipher info
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        # Check for known weak ciphers
                        weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']
                        for pattern in weak_patterns:
                            if pattern in cipher_name:
                                weak_ciphers.append(cipher_name)
                                break
        except Exception as e:
            logger.error("Failed to check weak ciphers", host=host, port=port, error=str(e))

        return weak_ciphers

    async def _check_ssl_versions(self, host: str, port: int) -> List[str]:
        """Check supported SSL/TLS versions"""
        supported_versions = []

        # Test different SSL/TLS versions
        versions_to_test = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),
            ('SSLv3', ssl.PROTOCOL_SSLv23),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
        ]

        for version_name, protocol in versions_to_test:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        supported_versions.append(version_name)
            except:
                continue

        return supported_versions

    def _resolve_target(self, target: str) -> Optional[str]:
        """Resolve target to IP address"""
        try:
            # Check if already an IP
            ipaddress.ip_address(target)
            return target
        except ValueError:
            # Resolve hostname
            try:
                return socket.gethostbyname(target)
            except socket.gaierror:
                return None

    async def _check_infrastructure_vulns(self, target_ip: str, vulnerabilities: List[Dict]):
        """Check for infrastructure vulnerabilities"""
        # Check for private IP exposure
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            if ip_obj.is_private:
                vulnerabilities.append({
                    'title': 'Private IP Address Exposure',
                    'description': f'Private IP address {target_ip} is exposed',
                    'severity': 'low',
                    'category': 'information_disclosure',
                    'target_host': target_ip,
                    'proof_of_concept': f'Private IP {target_ip} is accessible',
                    'recommendation': 'Ensure private IPs are not exposed to public networks'
                })
        except ValueError:
            pass

    async def _enumerate_services(self, target_ip: str) -> List[Dict]:
        """Enumerate services on target"""
        services = []

        # Common ports to check
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    services.append({
                        'ip': target_ip,
                        'port': port,
                        'state': 'open',
                        'service': self._get_service_name(port)
                    })

                sock.close()
            except:
                continue

        return services

    async def _analyze_configurations(self, target_ip: str, services: List[Dict]) -> List[Dict]:
        """Analyze service configurations for vulnerabilities"""
        vulnerabilities = []

        for service in services:
            port = service['port']
            service_name = service['service']

            # Check for default configurations
            if service_name == 'mysql' and port == 3306:
                vulnerabilities.append({
                    'title': 'MySQL Service Exposed',
                    'description': 'MySQL database service is exposed on default port',
                    'severity': 'high',
                    'category': 'exposed_service',
                    'target_host': target_ip,
                    'target_port': port,
                    'target_service': service_name,
                    'proof_of_concept': f'MySQL running on port {port}',
                    'recommendation': 'Restrict MySQL access to authorized hosts only'
                })

            elif service_name == 'redis' and port == 6379:
                vulnerabilities.append({
                    'title': 'Redis Service Exposed',
                    'description': 'Redis database service is exposed on default port',
                    'severity': 'high',
                    'category': 'exposed_service',
                    'target_host': target_ip,
                    'target_port': port,
                    'target_service': service_name,
                    'proof_of_concept': f'Redis running on port {port}',
                    'recommendation': 'Secure Redis with authentication and firewall rules'
                })

        return vulnerabilities

    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        port_mapping = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1433: 'mssql',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            6379: 'redis',
            27017: 'mongodb'
        }
        return port_mapping.get(port, 'unknown')

    def _is_vulnerable_openssh_version(self, version: str) -> bool:
        """Check if OpenSSH version is vulnerable"""
        # This is a simplified check - real implementation would have comprehensive CVE database
        vulnerable_versions = [
            '7.4', '7.3', '7.2', '7.1', '7.0',
            '6.9', '6.8', '6.7', '6.6', '6.5'
        ]

        for vuln_version in vulnerable_versions:
            if version.startswith(vuln_version):
                return True

        return False

    def _build_nmap_args(self, options: Dict[str, Any]) -> str:
        """Build nmap command arguments from options"""
        args = []

        if options.get('tcp_scan', True):
            args.append('-sS')

        if options.get('udp_scan', False):
            args.append('-sU')

        if options.get('service_detection', True):
            args.append('-sV')

        if options.get('os_detection', False):
            args.append('-O')

        if options.get('script_scan', False):
            args.append('-sC')

        if options.get('aggressive', False):
            args.append('-A')

        # Timing template
        timing = options.get('timing', 'normal')
        timing_map = {
            'paranoid': '-T0',
            'sneaky': '-T1',
            'polite': '-T2',
            'normal': '-T3',
            'aggressive': '-T4',
            'insane': '-T5'
        }
        args.append(timing_map.get(timing, '-T3'))

        return ' '.join(args)

    async def _process_scan_results(self, scan: Scan, result: ScanResult):
        """Process scan results and create vulnerability records"""
        try:
            for vuln_data in result.vulnerabilities:
                # Create vulnerability record
                vulnerability = Vulnerability(
                    title=vuln_data.get('title', 'Unknown Vulnerability'),
                    description=vuln_data.get('description', 'No description provided'),
                    severity=self._map_severity(vuln_data.get('severity', 'medium')),
                    category=vuln_data.get('category', 'unknown'),
                    target_host=vuln_data.get('target_host', scan.target),
                    target_port=vuln_data.get('target_port'),
                    target_service=vuln_data.get('target_service'),
                    target_path=vuln_data.get('target_path'),
                    proof_of_concept=vuln_data.get('proof_of_concept'),
                    recommendation=vuln_data.get('recommendation'),
                    cve_id=vuln_data.get('cve_id'),
                    cwe_id=vuln_data.get('cwe_id'),
                    cvss_score=vuln_data.get('cvss_score'),
                    risk_score=vuln_data.get('risk_score'),
                    raw_output=vuln_data.get('raw_output'),
                    scan_id=scan.id
                )

                # AI analysis if enabled
                if self.ai_service:
                    try:
                        ai_response = await self.ai_service.analyze_vulnerability(vuln_data)
                        vulnerability.ai_analysis = ai_response.scan_metadata.get('analysis', {})
                        vulnerability.ai_confidence = ai_response.confidence
                    except Exception as e:
                        logger.warning("AI analysis failed for vulnerability", error=str(e))

                db.session.add(vulnerability)

            # Update scan vulnerability counts
            scan.update_vulnerability_counts()
            db.session.commit()

        except Exception as e:
            logger.error("Failed to process scan results", error=str(e))
            db.session.rollback()
            raise

    def _map_severity(self, severity: str) -> VulnerabilitySeverity:
        """Map severity string to enum"""
        severity_map = {
            'critical': VulnerabilitySeverity.CRITICAL,
            'high': VulnerabilitySeverity.HIGH,
            'medium': VulnerabilitySeverity.MEDIUM,
            'low': VulnerabilitySeverity.LOW,
            'info': VulnerabilitySeverity.INFO
        }
        return severity_map.get(severity.lower(), VulnerabilitySeverity.MEDIUM)

    def _get_scan_url(self, scan_id: int) -> str:
        """
        Get scan URL
        """
        return f"https://your-domain.com/scans/{scan_id}"

    def get_supported_tools(self) -> Dict[str, Any]:
        """
        Get supported tools
        """
        return {
            'nmap': {
                'name': 'Nmap',
                'type': 'network',
                'description': 'Port scanner',
                'supported_options': ['tcp_scan', 'udp_scan', 'service_detection', 'os_detection', 'script_scan', 'aggressive']
            },
            'nikto': {
                'name': 'Nikto',
                'type': 'web',
                'description': 'Web server scanner',
                'supported_options': ['ssl_scan', 'cgi_scan', 'plugin_scan']
            },
            'sqlmap': {
                'name': 'SQLMap',
                'type': 'web',
                'description': 'SQL injection testing',
                'supported_options': ['database_fingerprint', 'data_extraction', 'file_system_access']
            },
            'dirb': {
                'name': 'DirB',
                'type': 'web',
                'description': 'Directory and file brute forcer',
                'supported_options': ['recursive_scan', 'extension_scan', 'custom_wordlist']
            },
            'sslyze': {
                'name': 'SSLyze',
                'type': 'ssl',
                'description': 'SSL/TLS configuration analyzer',
                'supported_options': ['certificate_info', 'cipher_suites', 'protocol_versions']
            }
        }