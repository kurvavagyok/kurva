# JADE Ultimate Security Platform - Email Service
# Advanced email notifications and alerts

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional, Dict, Any
from datetime import datetime
from jinja2 import Template
from flask import current_app
from flask_mail import Mail, Message
from config import Config
from utils.logger import get_logger

logger = get_logger(__name__)

class EmailService:
    """Advanced email service for notifications and alerts"""
    
    def __init__(self):
        self.smtp_server = Config.MAIL_SERVER
        self.smtp_port = Config.MAIL_PORT
        self.smtp_username = Config.MAIL_USERNAME
        self.smtp_password = Config.MAIL_PASSWORD
        self.sender_email = Config.MAIL_DEFAULT_SENDER
        self.use_tls = True
        
        # Email templates
        self.templates = {
            'vulnerability_alert': self._get_vulnerability_alert_template(),
            'scan_complete': self._get_scan_complete_template(),
            'security_report': self._get_security_report_template(),
            'user_registration': self._get_user_registration_template(),
            'password_reset': self._get_password_reset_template(),
            'security_breach': self._get_security_breach_template()
        }
    
    def send_vulnerability_alert(self, user_email: str, vulnerability_data: Dict) -> bool:
        """Send vulnerability alert email"""
        try:
            template = self.templates['vulnerability_alert']
            
            html_content = template.render(
                vulnerability=vulnerability_data,
                user_email=user_email,
                timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            )
            
            subject = f"🚨 JADE Security Alert: {vulnerability_data.get('severity', 'Unknown').upper()} Vulnerability Detected"
            
            return self._send_email(
                to_email=user_email,
                subject=subject,
                html_content=html_content,
                priority='high' if vulnerability_data.get('severity') in ['critical', 'high'] else 'normal'
            )
            
        except Exception as e:
            logger.error(f"Vulnerability alert email error: {str(e)}")
            return False
    
    def send_scan_complete_notification(self, user_email: str, scan_data: Dict) -> bool:
        """Send scan completion notification"""
        try:
            template = self.templates['scan_complete']
            
            html_content = template.render(
                scan=scan_data,
                user_email=user_email,
                timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            )
            
            subject = f"✅ JADE Security: Scan '{scan_data.get('name', 'Unknown')}' Completed"
            
            return self._send_email(
                to_email=user_email,
                subject=subject,
                html_content=html_content
            )
            
        except Exception as e:
            logger.error(f"Scan complete notification error: {str(e)}")
            return False
    
    def send_security_report(self, user_email: str, report_data: Dict, attachment_path: Optional[str] = None) -> bool:
        """Send security report email"""
        try:
            template = self.templates['security_report']
            
            html_content = template.render(
                report=report_data,
                user_email=user_email,
                timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            )
            
            subject = f"📊 JADE Security Report: {report_data.get('name', 'Security Report')}"
            
            return self._send_email(
                to_email=user_email,
                subject=subject,
                html_content=html_content,
                attachment_path=attachment_path
            )
            
        except Exception as e:
            logger.error(f"Security report email error: {str(e)}")
            return False
    
    def send_user_registration_email(self, user_email: str, user_data: Dict) -> bool:
        """Send user registration welcome email"""
        try:
            template = self.templates['user_registration']
            
            html_content = template.render(
                user=user_data,
                login_url=f"{current_app.config.get('APP_URL', 'http://localhost:5000')}/login",
                timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            )
            
            subject = "🎉 Welcome to JADE Ultimate Security Platform"
            
            return self._send_email(
                to_email=user_email,
                subject=subject,
                html_content=html_content
            )
            
        except Exception as e:
            logger.error(f"User registration email error: {str(e)}")
            return False
    
    def send_password_reset_email(self, user_email: str, reset_token: str) -> bool:
        """Send password reset email"""
        try:
            template = self.templates['password_reset']
            
            reset_url = f"{current_app.config.get('APP_URL', 'http://localhost:5000')}/reset-password?token={reset_token}"
            
            html_content = template.render(
                user_email=user_email,
                reset_url=reset_url,
                timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            )
            
            subject = "🔒 JADE Security: Password Reset Request"
            
            return self._send_email(
                to_email=user_email,
                subject=subject,
                html_content=html_content,
                priority='high'
            )
            
        except Exception as e:
            logger.error(f"Password reset email error: {str(e)}")
            return False
    
    def send_security_breach_alert(self, admin_emails: List[str], breach_data: Dict) -> bool:
        """Send security breach alert to administrators"""
        try:
            template = self.templates['security_breach']
            
            html_content = template.render(
                breach=breach_data,
                timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            )
            
            subject = "🚨 CRITICAL: JADE Security Breach Detected"
            
            success = True
            for admin_email in admin_emails:
                result = self._send_email(
                    to_email=admin_email,
                    subject=subject,
                    html_content=html_content,
                    priority='urgent'
                )
                if not result:
                    success = False
            
            return success
            
        except Exception as e:
            logger.error(f"Security breach alert error: {str(e)}")
            return False
    
    def _send_email(self, to_email: str, subject: str, html_content: str, 
                   text_content: Optional[str] = None, attachment_path: Optional[str] = None,
                   priority: str = 'normal') -> bool:
        """Send email using SMTP"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Set priority
            if priority == 'urgent':
                msg['X-Priority'] = '1'
                msg['X-MSMail-Priority'] = 'High'
            elif priority == 'high':
                msg['X-Priority'] = '2'
                msg['X-MSMail-Priority'] = 'High'
            
            # Add text content
            if text_content:
                text_part = MIMEText(text_content, 'plain')
                msg.attach(text_part)
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Add attachment if provided
            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {os.path.basename(attachment_path)}'
                    )
                    msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.use_tls:
                server.starttls()
            
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Email sending error: {str(e)}")
            return False
    
    def _get_vulnerability_alert_template(self) -> Template:
        """Get vulnerability alert email template"""
        template_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>JADE Security Alert</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .severity-critical { color: #dc3545; font-weight: bold; }
                .severity-high { color: #fd7e14; font-weight: bold; }
                .severity-medium { color: #ffc107; font-weight: bold; }
                .severity-low { color: #28a745; font-weight: bold; }
                .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
                .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 Security Alert</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <div class="content">
                    <h2>Vulnerability Detected</h2>
                    <p>A <span class="severity-{{ vulnerability.severity }}">{{ vulnerability.severity.upper() }}</span> vulnerability has been detected in your security scan.</p>
                    
                    <h3>Vulnerability Details:</h3>
                    <ul>
                        <li><strong>Title:</strong> {{ vulnerability.title }}</li>
                        <li><strong>Severity:</strong> <span class="severity-{{ vulnerability.severity }}">{{ vulnerability.severity.upper() }}</span></li>
                        <li><strong>Affected Asset:</strong> {{ vulnerability.affected_asset }}</li>
                        {% if vulnerability.cvss_score %}
                        <li><strong>CVSS Score:</strong> {{ vulnerability.cvss_score }}</li>
                        {% endif %}
                        {% if vulnerability.cve_id %}
                        <li><strong>CVE ID:</strong> {{ vulnerability.cve_id }}</li>
                        {% endif %}
                    </ul>
                    
                    <h3>Description:</h3>
                    <p>{{ vulnerability.description }}</p>
                    
                    {% if vulnerability.solution %}
                    <h3>Recommended Solution:</h3>
                    <p>{{ vulnerability.solution }}</p>
                    {% endif %}
                    
                    <a href="#" class="button">View Full Report</a>
                </div>
                
                <div class="footer">
                    <p>This alert was generated automatically by JADE Ultimate Security Platform</p>
                    <p>Time: {{ timestamp }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        return Template(template_content)
    
    def _get_scan_complete_template(self) -> Template:
        """Get scan completion email template"""
        template_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Scan Complete</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { background-color: #28a745; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .stats { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
                .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
                .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Scan Complete</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <div class="content">
                    <h2>Security Scan Completed</h2>
                    <p>Your security scan "{{ scan.name }}" has been completed successfully.</p>
                    
                    <div class="stats">
                        <h3>Scan Summary:</h3>
                        <ul>
                            <li><strong>Target:</strong> {{ scan.target }}</li>
                            <li><strong>Type:</strong> {{ scan.scan_type }}</li>
                            <li><strong>Status:</strong> {{ scan.status }}</li>
                            <li><strong>Duration:</strong> {{ scan.duration }}</li>
                            <li><strong>Vulnerabilities Found:</strong> {{ scan.vulnerabilities_count }}</li>
                        </ul>
                    </div>
                    
                    <p>You can now view the detailed results and generate reports from your dashboard.</p>
                    
                    <a href="#" class="button">View Results</a>
                </div>
                
                <div class="footer">
                    <p>JADE Ultimate Security Platform - Advanced AI-Powered Security</p>
                    <p>Time: {{ timestamp }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        return Template(template_content)
    
    def _get_security_report_template(self) -> Template:
        """Get security report email template"""
        template_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .report-info { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
                .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
                .button { display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 Security Report</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <div class="content">
                    <h2>Security Report Generated</h2>
                    <p>Your security report "{{ report.name }}" has been generated and is ready for download.</p>
                    
                    <div class="report-info">
                        <h3>Report Details:</h3>
                        <ul>
                            <li><strong>Report Type:</strong> {{ report.report_type }}</li>
                            <li><strong>Format:</strong> {{ report.format }}</li>
                            <li><strong>Generated:</strong> {{ report.generated_at }}</li>
                            <li><strong>Scan Target:</strong> {{ report.scan_target }}</li>
                        </ul>
                    </div>
                    
                    <p>The report contains detailed analysis of your security posture including vulnerabilities, risk assessment, and recommendations.</p>
                    
                    <a href="#" class="button">Download Report</a>
                </div>
                
                <div class="footer">
                    <p>JADE Ultimate Security Platform - AI-Powered Security Intelligence</p>
                    <p>Time: {{ timestamp }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        return Template(template_content)
    
    def _get_user_registration_template(self) -> Template:
        """Get user registration email template"""
        template_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Welcome to JADE</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { background-color: #6f42c1; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .welcome { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
                .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
                .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Welcome to JADE</h1>
                    <p>Ultimate Security Platform</p>
                </div>
                
                <div class="content">
                    <h2>Welcome {{ user.full_name }}!</h2>
                    <p>Thank you for joining JADE Ultimate Security Platform. Your account has been created successfully.</p>
                    
                    <div class="welcome">
                        <h3>Getting Started:</h3>
                        <ul>
                            <li>Log in to your dashboard</li>
                            <li>Configure your first security scan</li>
                            <li>Explore AI-powered analysis features</li>
                            <li>Set up automated alerts and reports</li>
                        </ul>
                    </div>
                    
                    <p>JADE provides enterprise-grade security scanning, threat intelligence, and AI-powered analysis to protect your digital assets.</p>
                    
                    <a href="{{ login_url }}" class="button">Access Dashboard</a>
                </div>
                
                <div class="footer">
                    <p>JADE Ultimate Security Platform - Protecting Your Digital Future</p>
                    <p>Time: {{ timestamp }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        return Template(template_content)
    
    def _get_password_reset_template(self) -> Template:
        """Get password reset email template"""
        template_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Password Reset</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { background-color: #ffc107; color: black; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .security-notice { background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #ffc107; }
                .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
                .button { display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Password Reset</h1>
                    <p>JADE Ultimate Security Platform</p>
                </div>
                
                <div class="content">
                    <h2>Password Reset Request</h2>
                    <p>We received a request to reset your password for your JADE account.</p>
                    
                    <div class="security-notice">
                        <h3>⚠️ Security Notice:</h3>
                        <ul>
                            <li>This link expires in 1 hour</li>
                            <li>Use this link only once</li>
                            <li>If you didn't request this, please ignore this email</li>
                        </ul>
                    </div>
                    
                    <p>Click the button below to reset your password:</p>
                    
                    <a href="{{ reset_url }}" class="button">Reset Password</a>
                    
                    <p>If the button doesn't work, copy and paste this URL into your browser:</p>
                    <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px;">{{ reset_url }}</p>
                </div>
                
                <div class="footer">
                    <p>JADE Ultimate Security Platform - Your Security is Our Priority</p>
                    <p>Time: {{ timestamp }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        return Template(template_content)
    
    def _get_security_breach_template(self) -> Template:
        """Get security breach alert email template"""
        template_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>CRITICAL: Security Breach</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
                .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .critical-alert { background-color: #f8d7da; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #dc3545; }
                .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
                .button { display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 CRITICAL ALERT</h1>
                    <p>Security Breach Detected</p>
                </div>
                
                <div class="content">
                    <h2>Security Breach Detected</h2>
                    <p>JADE Ultimate Security Platform has detected a potential security breach in your system.</p>
                    
                    <div class="critical-alert">
                        <h3>🔴 IMMEDIATE ACTION REQUIRED</h3>
                        <p><strong>Breach Type:</strong> {{ breach.breach_type }}</p>
                        <p><strong>Severity:</strong> {{ breach.severity }}</p>
                        <p><strong>Affected Systems:</strong> {{ breach.affected_systems }}</p>
                        <p><strong>Detection Time:</strong> {{ breach.detection_time }}</p>
                    </div>
                    
                    <h3>Recommended Actions:</h3>
                    <ul>
                        <li>Immediately assess the scope of the breach</li>
                        <li>Isolate affected systems</li>
                        <li>Review security logs</li>
                        <li>Implement incident response procedures</li>
                        <li>Contact your security team</li>
                    </ul>
                    
                    <a href="#" class="button">Access Incident Dashboard</a>
                </div>
                
                <div class="footer">
                    <p>JADE Ultimate Security Platform - Emergency Response System</p>
                    <p>Time: {{ timestamp }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        return Template(template_content)
    
    def send_bulk_notifications(self, email_list: List[str], template_name: str, data: Dict) -> Dict:
        """Send bulk notifications to multiple users"""
        results = {
            'success': 0,
            'failed': 0,
            'errors': []
        }
        
        for email in email_list:
            try:
                if template_name == 'vulnerability_alert':
                    success = self.send_vulnerability_alert(email, data)
                elif template_name == 'scan_complete':
                    success = self.send_scan_complete_notification(email, data)
                elif template_name == 'security_report':
                    success = self.send_security_report(email, data)
                else:
                    success = False
                
                if success:
                    results['success'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append(f"Failed to send to {email}")
                    
            except Exception as e:
                results['failed'] += 1
                results['errors'].append(f"Error sending to {email}: {str(e)}")
        
        return results
    
    def validate_email_configuration(self) -> Dict:
        """Validate email configuration"""
        try:
            # Test SMTP connection
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.use_tls:
                server.starttls()
            
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            
            server.quit()
            
            return {
                'valid': True,
                'message': 'Email configuration is valid'
            }
            
        except Exception as e:
            return {
                'valid': False,
                'message': f'Email configuration error: {str(e)}'
            }

# Global email service instance
email_service = EmailService()

# Convenience functions
def send_vulnerability_alert(user_email: str, vulnerability_data: Dict) -> bool:
    """Convenience function for sending vulnerability alerts"""
    return email_service.send_vulnerability_alert(user_email, vulnerability_data)

def send_scan_complete_notification(user_email: str, scan_data: Dict) -> bool:
    """Convenience function for sending scan completion notifications"""
    return email_service.send_scan_complete_notification(user_email, scan_data)

def send_security_report(user_email: str, report_data: Dict, attachment_path: Optional[str] = None) -> bool:
    """Convenience function for sending security reports"""
    return email_service.send_security_report(user_email, report_data, attachment_path)
