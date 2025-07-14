# JADE Ultimate - Report Service
# Comprehensive report generation service with AI integration

import os
import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import structlog
from jinja2 import Template
import pdfkit
import html2text
from dataclasses import dataclass

from models import Report, Scan, Vulnerability, User, VulnerabilitySeverity
from app import db
from services.ai_service import AIService
from config import Config

logger = structlog.get_logger()

@dataclass
class ReportContext:
    title: str
    description: str
    report_type: str
    scan_data: Optional[Dict[str, Any]] = None
    vulnerabilities: List[Dict[str, Any]] = None
    summary_stats: Dict[str, Any] = None
    recommendations: List[str] = None
    compliance_info: Dict[str, Any] = None

class ReportService:
    """
    Comprehensive report generation service supporting multiple formats
    """

    def __init__(self):
        self.ai_service = AIService()
        self.report_templates = {
            'executive': self._generate_executive_report,
            'technical': self._generate_technical_report,
            'compliance': self._generate_compliance_report,
            'vulnerability': self._generate_vulnerability_report
        }

    async def generate_report(self, report_id: int) -> bool:
        """
        Generate report based on report configuration
        """
        try:
            report = Report.query.get(report_id)
            if not report:
                logger.error("Report not found", report_id=report_id)
                return False

            logger.info("Starting report generation", report_id=report.id, report_type=report.report_type)

            # Prepare report context
            context = await self._prepare_report_context(report)

            # Generate report content
            if report.report_type in self.report_templates:
                content = await self.report_templates[report.report_type](context, report)
            else:
                raise ValueError(f"Unsupported report type: {report.report_type}")

            # Update report with generated content
            report.content = content
            report.generation_time = (datetime.now(timezone.utc) - report.created_at).total_seconds()

            # Generate file if needed
            if report.format in ['pdf', 'html']:
                file_path = await self._generate_report_file(report, content)
                if file_path:
                    report.file_path = file_path
                    report.file_size = os.path.getsize(file_path)
                    report.file_hash = self._calculate_file_hash(file_path)

            db.session.commit()

            logger.info("Report generated successfully", report_id=report.id)
            return True

        except Exception as e:
            logger.error("Report generation failed", report_id=report_id, error=str(e))
            return False

    async def _prepare_report_context(self, report: Report) -> ReportContext:
        """
        Prepare context data for report generation
        """
        context = ReportContext(
            title=report.title,
            description=report.description,
            report_type=report.report_type
        )

        # Load scan data if report is linked to a scan
        if report.scan_id:
            scan = Scan.query.get(report.scan_id)
            if scan:
                context.scan_data = scan.to_dict()

                # Load vulnerabilities
                vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()
                context.vulnerabilities = [v.to_dict() for v in vulnerabilities]

                # Calculate summary statistics
                context.summary_stats = self._calculate_summary_stats(vulnerabilities)

        # Generate compliance information
        context.compliance_info = self._generate_compliance_info(context.vulnerabilities or [])

        return context

    async def _generate_executive_report(self, context: ReportContext, report: Report) -> Dict[str, Any]:
        """
        Generate executive summary report
        """
        try:
            # Use AI to generate executive summary
            if context.scan_data and self.ai_service:
                ai_response = await self.ai_service.generate_scan_report(
                    context.scan_data, 
                    "executive"
                )

                if ai_response.content:
                    # Parse AI-generated content
                    ai_content = ai_response.content

                    return {
                        'executive_summary': ai_content,
                        'key_findings': self._extract_key_findings(context.vulnerabilities or []),
                        'risk_assessment': self._generate_risk_assessment(context.vulnerabilities or []),
                        'business_impact': self._assess_business_impact(context.vulnerabilities or []),
                        'recommendations': self._generate_executive_recommendations(context.vulnerabilities or []),
                        'compliance_status': context.compliance_info,
                        'statistics': context.summary_stats,
                        'generated_at': datetime.now(timezone.utc).isoformat(),
                        'report_metadata': {
                            'type': 'executive',
                            'ai_generated': True,
                            'model_used': ai_response.model
                        }
                    }

            # Fallback to template-based generation
            return self._generate_template_executive_report(context)

        except Exception as e:
            logger.error("Failed to generate executive report", error=str(e))
            return self._generate_template_executive_report(context)

    async def _generate_technical_report(self, context: ReportContext, report: Report) -> Dict[str, Any]:
        """
        Generate detailed technical report
        """
        try:
            # Use AI to generate technical analysis
            if context.scan_data and self.ai_service:
                ai_response = await self.ai_service.generate_scan_report(
                    context.scan_data, 
                    "technical"
                )

                if ai_response.content:
                    return {
                        'technical_analysis': ai_response.content,
                        'methodology': self._generate_methodology(context.scan_data),
                        'network_topology': self._analyze_network_topology(context.scan_data),
                        'vulnerability_details': self._format_vulnerability_details(context.vulnerabilities or []),
                        'proof_of_concept': self._compile_proof_of_concept(context.vulnerabilities or []),
                        'remediation_guide': self._generate_template_remediation_guide(context.vulnerabilities or []),
                        'appendices': self._generate_appendices(context.scan_data),
                        'statistics': context.summary_stats,
                        'generated_at': datetime.now(timezone.utc).isoformat(),
                        'report_metadata': {
                            'type': 'technical',
                            'ai_generated': True,
                            'model_used': ai_response.model
                        }
                    }

            # Fallback to template-based generation
            return self._generate_template_technical_report(context)

        except Exception as e:
            logger.error("Failed to generate technical report", error=str(e))
            return self._generate_template_technical_report(context)

    async def _generate_compliance_report(self, context: ReportContext, report: Report) -> Dict[str, Any]:
        """
        Generate compliance report
        """
        return {
            'compliance_overview': self._generate_compliance_overview(context.vulnerabilities or []),
            'regulatory_requirements': self._map_regulatory_requirements(context.vulnerabilities or []),
            'compliance_gaps': self._identify_compliance_gaps(context.vulnerabilities or []),
            'remediation_priorities': self._prioritize_compliance_remediation(context.vulnerabilities or []),
            'audit_trail': self._generate_audit_trail(context.scan_data),
            'certifications': self._assess_certifications(context.vulnerabilities or []),
            'statistics': context.summary_stats,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'report_metadata': {
                'type': 'compliance',
                'ai_generated': False
            }
        }

    async def _generate_vulnerability_report(self, context: ReportContext, report: Report) -> Dict[str, Any]:
        """
        Generate vulnerability-focused report
        """
        return {
            'vulnerability_summary': self._generate_vulnerability_summary(context.vulnerabilities or []),
            'severity_analysis': self._analyze_severity_distribution(context.vulnerabilities or []),
            'vulnerability_categories': self._categorize_vulnerabilities(context.vulnerabilities or []),
            'exploitation_analysis': self._analyze_exploitation_potential(context.vulnerabilities or []),
            'remediation_roadmap': self._generate_template_remediation_guide(context.vulnerabilities or []),
            'risk_matrix': self._generate_risk_matrix(context.vulnerabilities or []),
            'statistics': context.summary_stats,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'report_metadata': {
                'type': 'vulnerability',
                'ai_generated': False
            }
        }

    def _calculate_summary_stats(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """
        Calculate summary statistics for vulnerabilities
        """
        if not vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'by_severity': {},
                'by_category': {},
                'remediation_status': {}
            }

        severity_counts = {}
        category_counts = {}
        status_counts = {}

        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Count by category
            category = vuln.category
            category_counts[category] = category_counts.get(category, 0) + 1

            # Count by status
            status = vuln.status
            status_counts[status] = status_counts.get(status, 0) + 1

        return {
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': severity_counts,
            'by_category': category_counts,
            'remediation_status': status_counts,
            'avg_cvss_score': sum(v.cvss_score or 0 for v in vulnerabilities) / len(vulnerabilities)
        }

    def _generate_compliance_info(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate compliance information
        """
        compliance_standards = ['GDPR', 'SOC2', 'ISO27001', 'NIST', 'PCI-DSS']
        compliance_status = {}

        for standard in compliance_standards:
            # Simplified compliance assessment
            critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
            high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']

            if critical_vulns:
                compliance_status[standard] = 'Non-Compliant'
            elif high_vulns:
                compliance_status[standard] = 'Partial Compliance'
            else:
                compliance_status[standard] = 'Compliant'

        return {
            'standards': compliance_status,
            'overall_status': 'Non-Compliant' if any(s == 'Non-Compliant' for s in compliance_status.values()) else 'Compliant',
            'recommendations': [
                'Address all critical vulnerabilities immediately',
                'Implement security controls for high-risk vulnerabilities',
                'Conduct regular compliance assessments'
            ]
        }

    def _extract_key_findings(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract key findings from vulnerabilities
        """
        # Sort by severity and select top findings
        sorted_vulns = sorted(vulnerabilities, 
                            key=lambda x: {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(x.get('severity', 'low'), 1),
                            reverse=True)

        key_findings = []
        for vuln in sorted_vulns[:10]:  # Top 10 findings
            key_findings.append({
                'title': vuln.get('title', 'Unknown'),
                'severity': vuln.get('severity', 'unknown'),
                'category': vuln.get('category', 'unknown'),
                'impact': vuln.get('impact', 'Not specified'),
                'recommendation': vuln.get('recommendation', 'No recommendation available')
            })

        return key_findings

    def _generate_risk_assessment(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate risk assessment
        """
        if not vulnerabilities:
            return {'overall_risk': 'Low', 'score': 0, 'factors': []}

        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        medium_count = len([v for v in vulnerabilities if v.get('severity') == 'medium'])

        # Calculate risk score
        risk_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2)

        if risk_score > 50:
            overall_risk = 'Critical'
        elif risk_score > 25:
            overall_risk = 'High'
        elif risk_score > 10:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'

        return {
            'overall_risk': overall_risk,
            'score': risk_score,
            'factors': [
                f'{critical_count} critical vulnerabilities',
                f'{high_count} high-severity vulnerabilities',
                f'{medium_count} medium-severity vulnerabilities'
            ]
        }

    def _assess_business_impact(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess business impact of vulnerabilities
        """
        impact_areas = {
            'data_breach': 0,
            'service_disruption': 0,
            'financial_loss': 0,
            'reputation_damage': 0,
            'regulatory_penalties': 0
        }

        for vuln in vulnerabilities:
            category = vuln.get('category', '').lower()
            severity = vuln.get('severity', 'low')

            # Map vulnerability categories to business impact
            if category in ['injection', 'authentication', 'sensitive_data']:
                impact_areas['data_breach'] += 3 if severity == 'critical' else 1
            elif category in ['dos', 'availability']:
                impact_areas['service_disruption'] += 3 if severity == 'critical' else 1
            elif category in ['security_misconfiguration', 'broken_access_control']:
                impact_areas['financial_loss'] += 2 if severity == 'high' else 1
                impact_areas['reputation_damage'] += 2 if severity == 'high' else 1

        return {
            'impact_areas': impact_areas,
            'estimated_cost': self._estimate_breach_cost(vulnerabilities),
            'recovery_time': self._estimate_recovery_time(vulnerabilities)
        }

    def _generate_executive_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """
        Generate executive-level recommendations
        """
        recommendations = []

        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'high'])

        if critical_count > 0:
            recommendations.append(f"Immediate action required: {critical_count} critical vulnerabilities need urgent remediation")

        if high_count > 0:
            recommendations.append(f"High priority: Address {high_count} high-severity vulnerabilities within 30 days")

        recommendations.extend([
            "Implement regular security assessments and penetration testing",
            "Establish incident response procedures and security monitoring",
            "Provide security awareness training for all employees",
            "Consider cyber insurance to mitigate financial risks"
        ])

        return recommendations

    def _generate_template_executive_report(self, context: ReportContext) -> Dict[str, Any]:
        """
        Generate executive report using templates
        """
        return {
            'executive_summary': f"Security assessment of {context.scan_data.get('target', 'Unknown')} completed",
            'key_findings': self._extract_key_findings(context.vulnerabilities or []),
            'risk_assessment': self._generate_risk_assessment(context.vulnerabilities or []),
            'business_impact': self._assess_business_impact(context.vulnerabilities or []),
            'recommendations': self._generate_executive_recommendations(context.vulnerabilities or []),
            'compliance_status': context.compliance_info,
            'statistics': context.summary_stats,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'report_metadata': {
                'type': 'executive',
                'ai_generated': False
            }
        }

    def _generate_template_technical_report(self, context: ReportContext) -> Dict[str, Any]:
        """
        Generate technical report using templates
        """
        return {
            'technical_analysis': 'Detailed technical analysis of security findings',
            'methodology': self._generate_methodology(context.scan_data),
            'network_topology': self._analyze_network_topology(context.scan_data),
            'vulnerability_details': self._format_vulnerability_details(context.vulnerabilities or []),
            'proof_of_concept': self._compile_proof_of_concept(context.vulnerabilities or []),
            'remediation_guide': self._generate_template_remediation_guide(context.vulnerabilities or []),
            'appendices': self._generate_appendices(context.scan_data),
            'statistics': context.summary_stats,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'report_metadata': {
                'type': 'technical',
                'ai_generated': False
            }
        }

    def _generate_methodology(self, scan_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate methodology section
        """
        if not scan_data:
            return {'approach': 'Manual assessment', 'tools': [], 'scope': 'Limited'}

        return {
            'approach': f"{scan_data.get('scan_type', 'Unknown')} security assessment",
            'tools': scan_data.get('metadata', {}).get('tools_used', []),
            'scope': f"Target: {scan_data.get('target', 'Unknown')}",
            'duration': f"{scan_data.get('duration', 0)} seconds",
            'timing': scan_data.get('started_at', 'Unknown')
        }

    def _analyze_network_topology(self, scan_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze network topology from scan data
        """
        if not scan_data:
            return {'hosts': [], 'services': [], 'ports': []}

        metadata = scan_data.get('metadata', {})
        return {
            'hosts_discovered': metadata.get('hosts_up', 0),
            'services_detected': metadata.get('services_detected', []),
            'open_ports': metadata.get('open_ports', 0),
            'os_detection': metadata.get('os_detection', {})
        }

    def _format_vulnerability_details(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format vulnerability details for technical report
        """
        formatted_vulns = []

        for vuln in vulnerabilities:
            formatted_vulns.append({
                'id': vuln.get('id'),
                'title': vuln.get('title'),
                'severity': vuln.get('severity'),
                'category': vuln.get('category'),
                'description': vuln.get('description'),
                'target': f"{vuln.get('target_host', 'Unknown')}:{vuln.get('target_port', 'Unknown')}",
                'service': vuln.get('target_service', 'Unknown'),
                'proof_of_concept': vuln.get('proof_of_concept', 'Not provided'),
                'impact': vuln.get('impact', 'Not specified'),
                'recommendation': vuln.get('recommendation', 'No recommendation'),
                'references': vuln.get('references', []),
                'cvss_score': vuln.get('cvss_score'),
                'cve_id': vuln.get('cve_id'),
                'cwe_id': vuln.get('cwe_id')
            })

        return formatted_vulns

    def _compile_proof_of_concept(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Compile proof of concept information
        """
        poc_list = []

        for vuln in vulnerabilities:
            if vuln.get('proof_of_concept'):
                poc_list.append({
                    'vulnerability': vuln.get('title'),
                    'severity': vuln.get('severity'),
                    'poc': vuln.get('proof_of_concept'),
                    'target': vuln.get('target_host')
                })

        return poc_list

    async def _generate_remediation_guide(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate remediation guide
        """
        if self.ai_service:
            try:
                ai_response = await self.ai_service.generate_remediation_plan(vulnerabilities)
                if ai_response.content:
                    return json.loads(ai_response.content)
            except Exception as e:
                logger.warning("AI remediation plan generation failed", error=str(e))

        # Fallback to template-based remediation
        return self._generate_template_remediation_guide(vulnerabilities)

    def _generate_template_remediation_guide(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate template-based remediation guide
        """
        remediation_steps = []

        # Group by severity
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'medium']

        if critical_vulns:
            remediation_steps.append({
                'priority': 'Critical',
                'timeline': 'Immediate (0-24 hours)',
                'vulnerabilities': [v.get('title') for v in critical_vulns],
                'actions': ['Patch immediately', 'Implement temporary controls', 'Monitor closely']
            })

        if high_vulns:
            remediation_steps.append({
                'priority': 'High',
                'timeline': 'Short-term (1-30 days)',
                'vulnerabilities': [v.get('title') for v in high_vulns],
                'actions': ['Schedule patching', 'Implement compensating controls', 'Test thoroughly']
            })

        if medium_vulns:
            remediation_steps.append({
                'priority': 'Medium',
                'timeline': 'Medium-term (1-3 months)',
                'vulnerabilities': [v.get('title') for v in medium_vulns],
                'actions': ['Plan remediation', 'Implement during maintenance window', 'Validate fixes']
            })

        return {
            'remediation_steps': remediation_steps,
            'resource_requirements': 'Varies by vulnerability complexity',
            'success_metrics': 'Vulnerability count reduction and security posture improvement'
        }

    def _generate_appendices(self, scan_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate appendices for technical report
        """
        if not scan_data:
            return {'raw_data': 'No scan data available', 'references': []}

        return {
            'raw_data': scan_data.get('results', {}),
            'scan_configuration': scan_data.get('config', {}),
            'references': [
                'OWASP Top 10 - https://owasp.org/www-project-top-ten/',
                'NIST Cybersecurity Framework - https://www.nist.gov/cyberframework',
                'CWE/SANS Top 25 - https://cwe.mitre.org/top25/'
            ]
        }

    async def _generate_remediation_roadmap(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate remediation roadmap
        """
        if self.ai_service:
            try:
                ai_response = await self.ai_service.generate_remediation_plan(vulnerabilities)
                if ai_response.content:
                    return json.loads(ai_response.content)
            except Exception:
                pass

        # Fallback implementation
        return self._generate_template_remediation_guide(vulnerabilities)

    def _estimate_breach_cost(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """
        Estimate potential breach cost
        """
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'high'])

        if critical_count > 0:
            return "$500K - $5M+"
        elif high_count > 0:
            return "$100K - $1M"
        else:
            return "$10K - $100K"

    def _estimate_recovery_time(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """
        Estimate recovery time
        """
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])

        if critical_count > 0:
            return "1-4 weeks"
        else:
            return "1-2 weeks"

    async def _generate_report_file(self, report: Report, content: Dict[str, Any]) -> Optional[str]:
        """
        Generate report file (PDF or HTML)
        """
        try:
            # Create reports directory if it doesn't exist
            reports_dir = 'reports'
            os.makedirs(reports_dir, exist_ok=True)

            filename = f"report_{report.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            if report.format == 'html':
                file_path = os.path.join(reports_dir, f"{filename}.html")
                html_content = self._generate_html_report(content, report)

                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)

                return file_path

            elif report.format == 'pdf':
                file_path = os.path.join(reports_dir, f"{filename}.pdf")
                html_content = self._generate_html_report(content, report)

                # Generate PDF from HTML
                try:
                    pdfkit.from_string(html_content, file_path)
                    return file_path
                except Exception as e:
                    logger.error("PDF generation failed", error=str(e))
                    return None

            return None

        except Exception as e:
            logger.error("Report file generation failed", error=str(e))
            return None

    def _generate_html_report(self, content: Dict[str, Any], report: Report) -> str:
        """
        Generate HTML report from content
        """
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { border-bottom: 2px solid #333; padding-bottom: 20px; }
                .section { margin: 30px 0; }
                .vulnerability { background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }
                .critical { border-left-color: #dc3545; }
                .high { border-left-color: #fd7e14; }
                .medium { border-left-color: #ffc107; }
                .low { border-left-color: #28a745; }
                .stats { display: flex; gap: 20px; }
                .stat-box { background: #e9ecef; padding: 15px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ title }}</h1>
                <p>Generated: {{ generated_at }}</p>
                <p>Report Type: {{ report_type }}</p>
            </div>

            <div class="section">
                <h2>Executive Summary</h2>
                <p>{{ executive_summary }}</p>
            </div>

            <div class="section">
                <h2>Statistics</h2>
                <div class="stats">
                    <div class="stat-box">
                        <h3>Total Vulnerabilities</h3>
                        <p>{{ total_vulnerabilities }}</p>
                    </div>
                    <div class="stat-box">
                        <h3>Critical</h3>
                        <p>{{ critical_count }}</p>
                    </div>
                    <div class="stat-box">
                        <h3>High</h3>
                        <p>{{ high_count }}</p>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>Key Findings</h2>
                {% for finding in key_findings %}
                <div class="vulnerability {{ finding.severity }}">
                    <h3>{{ finding.title }}</h3>
                    <p><strong>Severity:</strong> {{ finding.severity }}</p>
                    <p><strong>Category:</strong> {{ finding.category }}</p>
                    <p>{{ finding.impact }}</p>
                </div>
                {% endfor %}
            </div>

            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                {% for recommendation in recommendations %}
                    <li>{{ recommendation }}</li>
                {% endfor %}
                </ul>
            </div>
        </body>
        </html>
        """

        template = Template(html_template)

        # Prepare template variables
        template_vars = {
            'title': report.title,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'report_type': report.report_type.title(),
            'executive_summary': content.get('executive_summary', 'No summary available'),
            'total_vulnerabilities': content.get('statistics', {}).get('total_vulnerabilities', 0),
            'critical_count': content.get('statistics', {}).get('by_severity', {}).get('critical', 0),
            'high_count': content.get('statistics', {}).get('by_severity', {}).get('high', 0),
            'key_findings': content.get('key_findings', []),
            'recommendations': content.get('recommendations', [])
        }

        return template.render(**template_vars)

    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate file hash for integrity verification
        """
        import hashlib

        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)

        return hash_sha256.hexdigest()

    def _generate_compliance_overview(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate compliance overview
        """
        return {
            'total_findings': len(vulnerabilities),
            'compliance_score': max(0, 100 - len(vulnerabilities) * 5),
            'status': 'Compliant' if len(vulnerabilities) == 0 else 'Non-Compliant',
            'last_assessment': datetime.now().isoformat()
        }

    def _map_regulatory_requirements(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Map vulnerabilities to regulatory requirements
        """
        requirements = {
            'GDPR': [],
            'SOC2': [],
            'ISO27001': [],
            'PCI-DSS': [],
            'NIST': []
        }

        for vuln in vulnerabilities:
            category = vuln.get('category', '').lower()
            title = vuln.get('title', '')

            if 'encryption' in category or 'data' in category:
                requirements['GDPR'].append(title)
                requirements['PCI-DSS'].append(title)

            if 'access' in category or 'authentication' in category:
                requirements['SOC2'].append(title)
                requirements['ISO27001'].append(title)

            if 'monitoring' in category or 'logging' in category:
                requirements['NIST'].append(title)

        return requirements

    def _identify_compliance_gaps(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify compliance gaps
        """```python
        gaps = []

        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        for vuln in critical_vulns:
            gaps.append({
                'vulnerability': vuln.get('title'),
                'requirement': 'Critical Security Controls',
                'gap_description': f"Critical vulnerability '{vuln.get('title')}' violates security requirements",
                'impact': 'High',
                'remediation': vuln.get('recommendation', 'No recommendation provided')
            })

        return gaps

    def _prioritize_compliance_remediation(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize compliance remediation
        """
        priorities = []

        # Sort by severity
        sorted_vulns = sorted(vulnerabilities, 
                            key=lambda x: {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(x.get('severity', 'low'), 1),
                            reverse=True)

        for i, vuln in enumerate(sorted_vulns[:10]):  # Top 10 priorities
            priorities.append({
                'priority': i + 1,
                'vulnerability': vuln.get('title'),
                'severity': vuln.get('severity'),
                'compliance_impact': 'High' if vuln.get('severity') in ['critical', 'high'] else 'Medium',
                'timeline': 'Immediate' if vuln.get('severity') == 'critical' else '30 days',
                'remediation': vuln.get('recommendation', 'No recommendation provided')
            })

        return priorities

    def _generate_audit_trail(self, scan_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate audit trail
        """
        if not scan_data:
            return {'events': [], 'methodology': 'Manual review'}

        return {
            'scan_initiated': scan_data.get('created_at'),
            'scan_completed': scan_data.get('completed_at'),
            'duration': scan_data.get('duration'),
            'methodology': scan_data.get('scan_type'),
            'target': scan_data.get('target'),
            'tools_used': scan_data.get('metadata', {}).get('tools_used', []),
            'findings_count': scan_data.get('vulnerabilities_found', 0)
        }

    def _assess_certifications(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess impact on certifications
        """
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'high'])

        certifications = {
            'ISO27001': 'At Risk' if critical_count > 0 else 'Compliant',
            'SOC2': 'At Risk' if critical_count > 0 or high_count > 5 else 'Compliant',
            'PCI-DSS': 'At Risk' if critical_count > 0 else 'Compliant'
        }

        return {
            'current_status': certifications,
            'risk_level': 'High' if critical_count > 0 else 'Low',
            'recommendations': [
                'Address all critical vulnerabilities before next audit',
                'Implement continuous monitoring',
                'Maintain documentation of remediation efforts'
            ]
        }

    def _generate_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate vulnerability summary
        """
        return {
            'total_count': len(vulnerabilities),
            'by_severity': {
                'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
                'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                'low': len([v for v in vulnerabilities if v.get('severity') == 'low'])
            },
            'top_categories': self._get_top_categories(vulnerabilities),
            'remediation_status': self._get_remediation_status(vulnerabilities)
        }

    def _analyze_severity_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze severity distribution
        """
        total = len(vulnerabilities)
        if total == 0:
            return {'distribution': {}, 'trend': 'stable'}

        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        distribution = {k: (v / total) * 100 for k, v in severity_counts.items()}

        return {
            'distribution': distribution,
            'trend': 'concerning' if distribution.get('critical', 0) > 10 else 'stable'
        }

    def _categorize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorize vulnerabilities
        """
        categories = {}

        for vuln in vulnerabilities:
            category = vuln.get('category', 'unknown')
            if category not in categories:
                categories[category] = []

            categories[category].append({
                'title': vuln.get('title'),
                'severity': vuln.get('severity'),
                'target': vuln.get('target_host')
            })

        return categories

    def _analyze_exploitation_potential(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze exploitation potential
        """
        high_risk = []
        medium_risk = []
        low_risk = []

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            has_exploit = vuln.get('proof_of_concept') is not None

            if severity == 'critical' and has_exploit:
                high_risk.append(vuln.get('title'))
            elif severity in ['high', 'medium'] and has_exploit:
                medium_risk.append(vuln.get('title'))
            else:
                low_risk.append(vuln.get('title'))

        return {
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'overall_risk': 'High' if high_risk else 'Medium' if medium_risk else 'Low'
        }

    def _generate_risk_matrix(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate risk matrix
        """
        matrix = {
            'critical_high': 0,
            'critical_medium': 0,
            'critical_low': 0,
            'high_high': 0,
            'high_medium': 0,
            'high_low': 0,
            'medium_high': 0,
            'medium_medium': 0,
            'medium_low': 0,
            'low_high': 0,
            'low_medium': 0,
            'low_low': 0
        }

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            # Simplified likelihood assessment
            likelihood = 'high' if vuln.get('proof_of_concept') else 'medium'

            key = f"{severity}_{likelihood}"
            if key in matrix:
                matrix[key] += 1

        return matrix

    def _get_top_categories(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get top vulnerability categories
        """
        category_counts = {}

        for vuln in vulnerabilities:
            category = vuln.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1

        # Sort by count and return top 5
        sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)

        return [{'category': cat, 'count': count} for cat, count in sorted_categories[:5]]

    def _get_remediation_status(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Get remediation status
        """
        status_counts = {}

        for vuln in vulnerabilities:
            status = vuln.get('status', 'open')
            status_counts[status] = status_counts.get(status, 0) + 1

        return status_counts