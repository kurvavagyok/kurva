# JADE Ultimate - Email Service
# Comprehensive email notification service

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional, Dict, Any
from datetime import datetime
import structlog
from jinja2 import Template
import asyncio
import aiosmtplib

from config import Config
from models import User, Alert, Vulnerability, Scan

logger = structlog.get_logger()

class EmailService:
    """
    Comprehensive email notification service
    """
    
    def __init__(self):
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.smtp_username = Config.SMTP_USERNAME
        self.smtp_password = Config.SMTP_PASSWORD
        self.from_email = Config.EMAIL_FROM
        self.enabled = Config.ENABLE_EMAIL_NOTIFICATIONS
        
        # Email templates
        self.templates = {
            'alert_notification': self._get_alert_template(),
            'scan_completion': self._get_scan_completion_template(),
            'vulnerability_detected': self._get_vulnerability_template(),
            'report_generated': self._get_report_template(),
            'user_registration': self._get_user_registration_template(),
            'password_reset': self._get_password_reset_template()
        }
    
    async def send_alert_notification(self, alert: Alert, users: List[User]) -> bool:
        """
        Send alert notification to users
        """
        if not self.enabled:
            logger.info("Email notifications disabled")
            return True
        
        try:
            subject = f"Security Alert: {alert.title}"
            
            for user in users:
                template_data = {
                    'user_name': user.full_name(),
                    'alert_title': alert.title,
                    'alert_description': alert.description,
                    'alert_severity': alert.severity.value,
                    'alert_type': alert.alert_type,
                    'created_at': alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'dashboard_url': self._get_dashboard_url()
                }
                
                html_content = self._render_template('alert_notification', template_data)
                
                success = await self._send_email(
                    to_email=user.email,
                    subject=subject,
                    html_content=html_content
                )
                
                if success:
                    logger.info("Alert notification sent", 
                               alert_id=alert.id, 
                               user_id=user.id)
                else:
                    logger.error("Failed to send alert notification",
                                alert_id=alert.id,
                                user_id=user.id)
            
            return True
            
        except Exception as e:
            logger.error("Alert notification failed", error=str(e))
            return False
    
    async def send_scan_completion_notification(self, scan: Scan, user: User) -> bool:
        """
        Send scan completion notification
        """
        if not self.enabled:
            return True
        
        try:
            subject = f"Scan Completed: {scan.name}"
            
            template_data = {
                'user_name': user.full_name(),
                'scan_name': scan.name,
                'scan_target': scan.target,
                'scan_type': scan.scan_type,
                'status': scan.status.value,
                'duration': scan.duration,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'critical_vulns': scan.critical_vulns,
                'high_vulns': scan.high_vulns,
                'medium_vulns': scan.medium_vulns,
                'low_vulns': scan.low_vulns,
                'completed_at': scan.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.completed_at else 'Unknown',
                'scan_url': self._get_scan_url(scan.id)
            }
            
            html_content = self._render_template('scan_completion', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            if success:
                logger.info("Scan completion notification sent",
                           scan_id=scan.id,
                           user_id=user.id)
            
            return success
            
        except Exception as e:
            logger.error("Scan completion notification failed", error=str(e))
            return False
    
    async def send_vulnerability_notification(self, vulnerability: Vulnerability, users: List[User]) -> bool:
        """
        Send critical vulnerability notification
        """
        if not self.enabled:
            return True
        
        # Only send notifications for critical and high severity vulnerabilities
        if vulnerability.severity.value not in ['critical', 'high']:
            return True
        
        try:
            subject = f"Critical Vulnerability Detected: {vulnerability.title}"
            
            for user in users:
                template_data = {
                    'user_name': user.full_name(),
                    'vulnerability_title': vulnerability.title,
                    'vulnerability_description': vulnerability.description,
                    'severity': vulnerability.severity.value,
                    'category': vulnerability.category,
                    'target_host': vulnerability.target_host,
                    'target_port': vulnerability.target_port,
                    'recommendation': vulnerability.recommendation,
                    'cvss_score': vulnerability.cvss_score,
                    'cve_id': vulnerability.cve_id,
                    'discovered_at': vulnerability.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'vulnerability_url': self._get_vulnerability_url(vulnerability.id)
                }
                
                html_content = self._render_template('vulnerability_detected', template_data)
                
                success = await self._send_email(
                    to_email=user.email,
                    subject=subject,
                    html_content=html_content
                )
                
                if success:
                    logger.info("Vulnerability notification sent",
                               vulnerability_id=vulnerability.id,
                               user_id=user.id)
            
            return True
            
        except Exception as e:
            logger.error("Vulnerability notification failed", error=str(e))
            return False
    
    async def send_report_generated_notification(self, report_id: int, user: User, file_path: Optional[str] = None) -> bool:
        """
        Send report generation notification
        """
        if not self.enabled:
            return True
        
        try:
            from models import Report
            report = Report.query.get(report_id)
            if not report:
                logger.error("Report not found", report_id=report_id)
                return False
            
            subject = f"Report Generated: {report.title}"
            
            template_data = {
                'user_name': user.full_name(),
                'report_title': report.title,
                'report_type': report.report_type,
                'report_description': report.description,
                'generated_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'report_url': self._get_report_url(report.id),
                'download_available': file_path is not None
            }
            
            html_content = self._render_template('report_generated', template_data)
            
            # Attach report file if available
            attachments = []
            if file_path and os.path.exists(file_path):
                attachments.append({
                    'filename': os.path.basename(file_path),
                    'filepath': file_path
                })
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content,
                attachments=attachments
            )
            
            if success:
                logger.info("Report notification sent",
                           report_id=report.id,
                           user_id=user.id)
            
            return success
            
        except Exception as e:
            logger.error("Report notification failed", error=str(e))
            return False
    
    async def send_user_registration_notification(self, user: User, temp_password: str) -> bool:
        """
        Send user registration notification with temporary password
        """
        if not self.enabled:
            return True
        
        try:
            subject = "Welcome to JADE Ultimate Security Platform"
            
            template_data = {
                'user_name': user.full_name(),
                'username': user.username,
                'temp_password': temp_password,
                'login_url': self._get_login_url(),
                'support_email': self.from_email
            }
            
            html_content = self._render_template('user_registration', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            if success:
                logger.info("User registration notification sent", user_id=user.id)
            
            return success
            
        except Exception as e:
            logger.error("User registration notification failed", error=str(e))
            return False
    
    async def send_password_reset_notification(self, user: User, reset_token: str) -> bool:
        """
        Send password reset notification
        """
        if not self.enabled:
            return True
        
        try:
            subject = "Password Reset Request - JADE Ultimate"
            
            template_data = {
                'user_name': user.full_name(),
                'reset_url': self._get_password_reset_url(reset_token),
                'expiry_hours': 24,
                'support_email': self.from_email
            }
            
            html_content = self._render_template('password_reset', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            if success:
                logger.info("Password reset notification sent", user_id=user.id)
            
            return success
            
        except Exception as e:
            logger.error("Password reset notification failed", error=str(e))
            return False
    
    async def send_bulk_notification(self, users: List[User], subject: str, template_name: str, template_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Send bulk notification to multiple users
        """
        if not self.enabled:
            return {user.email: True for user in users}
        
        results = {}
        
        for user in users:
            try:
                # Personalize template data for each user
                personalized_data = template_data.copy()
                personalized_data['user_name'] = user.full_name()
                
                html_content = self._render_template(template_name, personalized_data)
                
                success = await self._send_email(
                    to_email=user.email,
                    subject=subject,
                    html_content=html_content
                )
                
                results[user.email] = success
                
            except Exception as e:
                logger.error("Bulk notification failed for user",
                            user_id=user.id,
                            error=str(e))
                results[user.email] = False
        
        return results
    
    async def _send_email(self, to_email: str, subject: str, html_content: str, attachments: Optional[List[Dict[str, str]]] = None) -> bool:
        """
        Send email using SMTP
        """
        try:
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.from_email
            message['To'] = to_email
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            message.attach(html_part)
            
            # Add attachments if provided
            if attachments:
                for attachment in attachments:
                    if os.path.exists(attachment['filepath']):
                        with open(attachment['filepath'], 'rb') as f:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(f.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= {attachment["filename"]}'
                            )
                            message.attach(part)
            
            # Send email using aiosmtplib for async support
            await aiosmtplib.send(
                message,
                hostname=self.smtp_server,
                port=self.smtp_port,
                username=self.smtp_username,
                password=self.smtp_password,
                use_tls=True
            )
            
            logger.info("Email sent successfully", to_email=to_email)
            return True
            
        except Exception as e:
            logger.error("Email sending failed", to_email=to_email, error=str(e))
            return False
    
    def _render_template(self, template_name: str, data: Dict[str, Any]) -> str:
        """
        Render email template with data
        """
        if template_name not in self.templates:
            logger.error("Template not found", template_name=template_name)
            return "Template not found"
        
        template = Template(self.templates[template_name])
        return template.render(**data)
    
    def _get_alert_template(self) -> str:
        """
        Get alert notification template
        """
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; }
                .header { background-color: #dc3545; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .severity { padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
                .critical { background-color: #dc3545; }
                .high { background-color: #fd7e14; }
                .medium { background-color: #ffc107; color: black; }
                .low { background-color: #28a745; }
                .button { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Alert</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <h2>Hello {{ user_name }},</h2>
                
                <p>A new security alert has been detected:</p>
                
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h3>{{ alert_title }}</h3>
                    <p><strong>Severity:</strong> <span class="severity {{ alert_severity }}">{{ alert_severity.upper() }}</span></p>
                    <p><strong>Type:</strong> {{ alert_type }}</p>
                    <p><strong>Description:</strong> {{ alert_description }}</p>
                    <p><strong>Detected:</strong> {{ created_at }}</p>
                </div>
                
                <p>Please review this alert and take appropriate action.</p>
                
                <a href="{{ dashboard_url }}" class="button">View Dashboard</a>
                
                <hr style="margin: 30px 0;">
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from JADE Ultimate Security Platform.
                    Do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """
    
    def _get_scan_completion_template(self) -> str:
        """
        Get scan completion template
        """
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; }
                .header { background-color: #28a745; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .stats { display: flex; justify-content: space-around; margin: 20px 0; }
                .stat { text-align: center; }
                .stat-number { font-size: 24px; font-weight: bold; color: #007bff; }
                .button { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Scan Completed</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <h2>Hello {{ user_name }},</h2>
                
                <p>Your security scan has been completed successfully.</p>
                
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h3>Scan Details</h3>
                    <p><strong>Name:</strong> {{ scan_name }}</p>
                    <p><strong>Target:</strong> {{ scan_target }}</p>
                    <p><strong>Type:</strong> {{ scan_type }}</p>
                    <p><strong>Status:</strong> {{ status }}</p>
                    <p><strong>Duration:</strong> {{ duration }} seconds</p>
                    <p><strong>Completed:</strong> {{ completed_at }}</p>
                </div>
                
                <h3>Vulnerabilities Found</h3>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-number" style="color: #dc3545;">{{ critical_vulns }}</div>
                        <div>Critical</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" style="color: #fd7e14;">{{ high_vulns }}</div>
                        <div>High</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" style="color: #ffc107;">{{ medium_vulns }}</div>
                        <div>Medium</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" style="color: #28a745;">{{ low_vulns }}</div>
                        <div>Low</div>
                    </div>
                </div>
                
                <p>Total vulnerabilities found: <strong>{{ vulnerabilities_found }}</strong></p>
                
                <a href="{{ scan_url }}" class="button">View Scan Results</a>
                
                <hr style="margin: 30px 0;">
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from JADE Ultimate Security Platform.
                    Do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """
    
    def _get_vulnerability_template(self) -> str:
        """
        Get vulnerability notification template
        """
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; }
                .header { background-color: #dc3545; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .severity { padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
                .critical { background-color: #dc3545; }
                .high { background-color: #fd7e14; }
                .button { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Critical Vulnerability Detected</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <h2>Hello {{ user_name }},</h2>
                
                <p>A critical vulnerability has been detected in your environment:</p>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h3>{{ vulnerability_title }}</h3>
                    <p><strong>Severity:</strong> <span class="severity {{ severity }}">{{ severity.upper() }}</span></p>
                    <p><strong>Category:</strong> {{ category }}</p>
                    <p><strong>Target:</strong> {{ target_host }}:{{ target_port }}</p>
                    {% if cvss_score %}
                    <p><strong>CVSS Score:</strong> {{ cvss_score }}</p>
                    {% endif %}
                    {% if cve_id %}
                    <p><strong>CVE ID:</strong> {{ cve_id }}</p>
                    {% endif %}
                    <p><strong>Discovered:</strong> {{ discovered_at }}</p>
                </div>
                
                <h3>Description</h3>
                <p>{{ vulnerability_description }}</p>
                
                <h3>Recommendation</h3>
                <p>{{ recommendation }}</p>
                
                <div style="background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <strong>⚠️ Immediate Action Required</strong>
                    <p>This vulnerability requires immediate attention. Please review and remediate as soon as possible.</p>
                </div>
                
                <a href="{{ vulnerability_url }}" class="button">View Vulnerability Details</a>
                
                <hr style="margin: 30px 0;">
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from JADE Ultimate Security Platform.
                    Do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """
    
    def _get_report_template(self) -> str:
        """
        Get report generation template
        """
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; }
                .header { background-color: #007bff; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .button { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Report Generated</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <h2>Hello {{ user_name }},</h2>
                
                <p>Your security report has been generated successfully.</p>
                
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h3>Report Details</h3>
                    <p><strong>Title:</strong> {{ report_title }}</p>
                    <p><strong>Type:</strong> {{ report_type }}</p>
                    <p><strong>Description:</strong> {{ report_description }}</p>
                    <p><strong>Generated:</strong> {{ generated_at }}</p>
                </div>
                
                {% if download_available %}
                <p>The report is attached to this email and also available for download from the platform.</p>
                {% endif %}
                
                <a href="{{ report_url }}" class="button">View Report</a>
                
                <hr style="margin: 30px 0;">
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from JADE Ultimate Security Platform.
                    Do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """
    
    def _get_user_registration_template(self) -> str:
        """
        Get user registration template
        """
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; }
                .header { background-color: #28a745; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .credentials { background-color: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .button { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to JADE Ultimate</h1>
                    <p>Security Platform</p>
                </div>
                
                <h2>Hello {{ user_name }},</h2>
                
                <p>Welcome to the JADE Ultimate Security Platform! Your account has been created successfully.</p>
                
                <div class="credentials">
                    <h3>Your Login Credentials</h3>
                    <p><strong>Username:</strong> {{ username }}</p>
                    <p><strong>Temporary Password:</strong> {{ temp_password }}</p>
                </div>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <strong>⚠️ Important Security Notice</strong>
                    <p>Please log in and change your password immediately. This temporary password will expire in 24 hours.</p>
                </div>
                
                <a href="{{ login_url }}" class="button">Log In Now</a>
                
                <h3>Getting Started</h3>
                <ul>
                    <li>Log in to your account using the credentials above</li>
                    <li>Change your password in the profile settings</li>
                    <li>Explore the dashboard and available features</li>
                    <li>Review the documentation and tutorials</li>
                </ul>
                
                <p>If you need any assistance, please contact our support team at <a href="mailto:{{ support_email }}">{{ support_email }}</a>.</p>
                
                <hr style="margin: 30px 0;">
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from JADE Ultimate Security Platform.
                    Do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """
    
    def _get_password_reset_template(self) -> str:
        """
        Get password reset template
        """
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; }
                .header { background-color: #ffc107; color: black; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .button { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Password Reset Request</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <h2>Hello {{ user_name }},</h2>
                
                <p>We received a request to reset your password for your JADE Ultimate Security Platform account.</p>
                
                <p>If you made this request, click the button below to reset your password:</p>
                
                <a href="{{ reset_url }}" class="button">Reset Password</a>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <strong>⚠️ Important</strong>
                    <p>This password reset link will expire in {{ expiry_hours }} hours. If you didn't request this reset, please ignore this email.</p>
                </div>
                
                <p>For security reasons, please do not share this link with anyone.</p>
                
                <p>If you need additional assistance, please contact our support team at <a href="mailto:{{ support_email }}">{{ support_email }}</a>.</p>
                
                <hr style="margin: 30px 0;">
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from JADE Ultimate Security Platform.
                    Do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """
    
    def _get_dashboard_url(self) -> str:
        """
        Get dashboard URL
        """
        return "https://your-domain.com/dashboard"
    
    def _get_scan_url(self, scan_id: int) -> str:
        """
        Get scan URL
        """
        return f"https://your-domain.com/scans/{scan_id}"
    
    def _get_vulnerability_url(self, vulnerability_id: int) -> str:
        """
        Get vulnerability URL
        """
        return f"https://your-domain.com/vulnerabilities/{vulnerability_id}"
    
    def _get_report_url(self, report_id: int) -> str:
        """
        Get report URL
        """
        return f"https://your-domain.com/reports/{report_id}"
    
    def _get_login_url(self) -> str:
        """
        Get login URL
        """
        return "https://your-domain.com/login"
    
    def _get_password_reset_url(self, reset_token: str) -> str:
        """
        Get password reset URL
        """
        return f"https://your-domain.com/reset-password?token={reset_token}"
