# JADE Ultimate - Dashboard API
# Dashboard data and statistics endpoints

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timezone, timedelta
import structlog

from app import db
from models import Scan, Vulnerability, Alert, Report, User, ScanStatus, VulnerabilitySeverity, AlertStatus
from utils.security import requires_role

logger = structlog.get_logger()

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/overview', methods=['GET'])
@login_required
def api_dashboard_overview():
    """
    Get dashboard overview statistics
    """
    try:
        # Basic statistics for current user
        total_scans = Scan.query.filter_by(user_id=current_user.id).count()
        active_scans = Scan.query.filter_by(
            user_id=current_user.id,
            status=ScanStatus.RUNNING
        ).count()
        completed_scans = Scan.query.filter_by(
            user_id=current_user.id,
            status=ScanStatus.COMPLETED
        ).count()
        failed_scans = Scan.query.filter_by(
            user_id=current_user.id,
            status=ScanStatus.FAILED
        ).count()
        
        # Vulnerability statistics
        total_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id
        ).count()
        
        critical_vulns = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.severity == VulnerabilitySeverity.CRITICAL
        ).count()
        
        high_vulns = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.severity == VulnerabilitySeverity.HIGH
        ).count()
        
        medium_vulns = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.severity == VulnerabilitySeverity.MEDIUM
        ).count()
        
        low_vulns = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.severity == VulnerabilitySeverity.LOW
        ).count()
        
        # Alert statistics
        total_alerts = Alert.query.filter_by(user_id=current_user.id).count()
        open_alerts = Alert.query.filter_by(
            user_id=current_user.id,
            status=AlertStatus.OPEN
        ).count()
        
        # Report statistics
        total_reports = Report.query.filter_by(user_id=current_user.id).count()
        
        # Recent activity (last 7 days)
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_scans = Scan.query.filter(
            Scan.user_id == current_user.id,
            Scan.created_at >= seven_days_ago
        ).count()
        
        recent_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.created_at >= seven_days_ago
        ).count()
        
        # Risk score calculation
        risk_score = calculate_risk_score(critical_vulns, high_vulns, medium_vulns, low_vulns)
        
        return jsonify({
            'overview': {
                'scans': {
                    'total': total_scans,
                    'active': active_scans,
                    'completed': completed_scans,
                    'failed': failed_scans,
                    'success_rate': (completed_scans / total_scans * 100) if total_scans > 0 else 0
                },
                'vulnerabilities': {
                    'total': total_vulnerabilities,
                    'critical': critical_vulns,
                    'high': high_vulns,
                    'medium': medium_vulns,
                    'low': low_vulns
                },
                'alerts': {
                    'total': total_alerts,
                    'open': open_alerts
                },
                'reports': {
                    'total': total_reports
                },
                'recent_activity': {
                    'scans': recent_scans,
                    'vulnerabilities': recent_vulnerabilities
                },
                'risk_score': risk_score
            }
        }), 200
        
    except Exception as e:
        logger.error("Dashboard overview API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@dashboard_bp.route('/recent-activity', methods=['GET'])
@login_required
def api_recent_activity():
    """
    Get recent activity for dashboard
    """
    try:
        limit = min(request.args.get('limit', 10, type=int), 50)
        
        # Recent scans
        recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(
            Scan.created_at.desc()
        ).limit(limit).all()
        
        # Recent vulnerabilities
        recent_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id
        ).order_by(Vulnerability.created_at.desc()).limit(limit).all()
        
        # Recent alerts
        recent_alerts = Alert.query.filter_by(user_id=current_user.id).order_by(
            Alert.created_at.desc()
        ).limit(limit).all()
        
        # Recent reports
        recent_reports = Report.query.filter_by(user_id=current_user.id).order_by(
            Report.created_at.desc()
        ).limit(limit).all()
        
        return jsonify({
            'recent_activity': {
                'scans': [scan.to_dict() for scan in recent_scans],
                'vulnerabilities': [vuln.to_dict() for vuln in recent_vulnerabilities],
                'alerts': [alert.to_dict() for alert in recent_alerts],
                'reports': [report.to_dict() for report in recent_reports]
            }
        }), 200
        
    except Exception as e:
        logger.error("Recent activity API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@dashboard_bp.route('/charts/vulnerability-trends', methods=['GET'])
@login_required
def api_vulnerability_trends():
    """
    Get vulnerability trends data for charts
    """
    try:
        days = min(request.args.get('days', 30, type=int), 365)
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Get vulnerability counts by day
        vulnerability_trends = db.session.query(
            db.func.date(Vulnerability.created_at).label('date'),
            Vulnerability.severity,
            db.func.count(Vulnerability.id).label('count')
        ).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.created_at >= start_date
        ).group_by(
            db.func.date(Vulnerability.created_at),
            Vulnerability.severity
        ).order_by(db.func.date(Vulnerability.created_at)).all()
        
        # Format data for charts
        trends_data = {}
        for date, severity, count in vulnerability_trends:
            date_str = date.isoformat()
            if date_str not in trends_data:
                trends_data[date_str] = {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            trends_data[date_str][severity.value] = count
        
        return jsonify({
            'vulnerability_trends': trends_data
        }), 200
        
    except Exception as e:
        logger.error("Vulnerability trends API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@dashboard_bp.route('/charts/scan-distribution', methods=['GET'])
@login_required
def api_scan_distribution():
    """
    Get scan type distribution data
    """
    try:
        # Scan type distribution
        scan_types = db.session.query(
            Scan.scan_type,
            db.func.count(Scan.id).label('count')
        ).filter_by(user_id=current_user.id).group_by(Scan.scan_type).all()
        
        scan_distribution = {scan_type: count for scan_type, count in scan_types}
        
        # Scan status distribution
        scan_statuses = db.session.query(
            Scan.status,
            db.func.count(Scan.id).label('count')
        ).filter_by(user_id=current_user.id).group_by(Scan.status).all()
        
        status_distribution = {status.value: count for status, count in scan_statuses}
        
        return jsonify({
            'scan_distribution': {
                'by_type': scan_distribution,
                'by_status': status_distribution
            }
        }), 200
        
    except Exception as e:
        logger.error("Scan distribution API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@dashboard_bp.route('/charts/risk-timeline', methods=['GET'])
@login_required
def api_risk_timeline():
    """
    Get risk timeline data
    """
    try:
        days = min(request.args.get('days', 30, type=int), 365)
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Calculate daily risk scores
        daily_risks = []
        current_date = start_date
        
        while current_date <= datetime.now(timezone.utc):
            # Get vulnerabilities up to this date
            vulns_by_severity = db.session.query(
                Vulnerability.severity,
                db.func.count(Vulnerability.id).label('count')
            ).join(Scan).filter(
                Scan.user_id == current_user.id,
                Vulnerability.created_at <= current_date,
                Vulnerability.remediated == False
            ).group_by(Vulnerability.severity).all()
            
            severity_counts = {severity.value: count for severity, count in vulns_by_severity}
            
            risk_score = calculate_risk_score(
                severity_counts.get('critical', 0),
                severity_counts.get('high', 0),
                severity_counts.get('medium', 0),
                severity_counts.get('low', 0)
            )
            
            daily_risks.append({
                'date': current_date.date().isoformat(),
                'risk_score': risk_score,
                'critical': severity_counts.get('critical', 0),
                'high': severity_counts.get('high', 0),
                'medium': severity_counts.get('medium', 0),
                'low': severity_counts.get('low', 0)
            })
            
            current_date += timedelta(days=1)
        
        return jsonify({
            'risk_timeline': daily_risks
        }), 200
        
    except Exception as e:
        logger.error("Risk timeline API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@dashboard_bp.route('/top-vulnerabilities', methods=['GET'])
@login_required
def api_top_vulnerabilities():
    """
    Get top vulnerabilities by severity and frequency
    """
    try:
        limit = min(request.args.get('limit', 10, type=int), 50)
        
        # Top vulnerabilities by severity
        top_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.remediated == False
        ).order_by(
            Vulnerability.severity.desc(),
            Vulnerability.cvss_score.desc(),
            Vulnerability.created_at.desc()
        ).limit(limit).all()
        
        # Most common vulnerability categories
        common_categories = db.session.query(
            Vulnerability.category,
            db.func.count(Vulnerability.id).label('count')
        ).join(Scan).filter(
            Scan.user_id == current_user.id
        ).group_by(Vulnerability.category).order_by(
            db.func.count(Vulnerability.id).desc()
        ).limit(10).all()
        
        return jsonify({
            'top_vulnerabilities': [vuln.to_dict() for vuln in top_vulnerabilities],
            'common_categories': [
                {'category': category, 'count': count}
                for category, count in common_categories
            ]
        }), 200
        
    except Exception as e:
        logger.error("Top vulnerabilities API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@dashboard_bp.route('/system-health', methods=['GET'])
@login_required
def api_system_health():
    """
    Get system health metrics (admin only)
    """
    try:
        if not current_user.is_admin():
            return jsonify({'error': 'Admin access required'}), 403
        
        # System-wide statistics
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        total_system_scans = Scan.query.count()
        running_system_scans = Scan.query.filter_by(status=ScanStatus.RUNNING).count()
        total_system_vulnerabilities = Vulnerability.query.count()
        
        # Recent activity (last 24 hours)
        twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_users = User.query.filter(User.last_login >= twenty_four_hours_ago).count()
        recent_system_scans = Scan.query.filter(Scan.created_at >= twenty_four_hours_ago).count()
        
        # Performance metrics (mock data - would be real metrics in production)
        system_metrics = {
            'cpu_usage': 45.2,
            'memory_usage': 62.8,
            'disk_usage': 34.1,
            'network_io': 123.4,
            'response_time': 89.5
        }
        
        return jsonify({
            'system_health': {
                'users': {
                    'total': total_users,
                    'active': active_users,
                    'recent_logins': recent_users
                },
                'scans': {
                    'total': total_system_scans,
                    'running': running_system_scans,
                    'recent': recent_system_scans
                },
                'vulnerabilities': {
                    'total': total_system_vulnerabilities
                },
                'metrics': system_metrics,
                'status': 'healthy' if running_system_scans < 10 else 'warning'
            }
        }), 200
        
    except Exception as e:
        logger.error("System health API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@dashboard_bp.route('/alerts/summary', methods=['GET'])
@login_required
def api_alerts_summary():
    """
    Get alerts summary for dashboard
    """
    try:
        # Alert statistics
        total_alerts = Alert.query.filter_by(user_id=current_user.id).count()
        open_alerts = Alert.query.filter_by(
            user_id=current_user.id,
            status=AlertStatus.OPEN
        ).count()
        acknowledged_alerts = Alert.query.filter_by(
            user_id=current_user.id,
            status=AlertStatus.ACKNOWLEDGED
        ).count()
        resolved_alerts = Alert.query.filter_by(
            user_id=current_user.id,
            status=AlertStatus.RESOLVED
        ).count()
        
        # Alerts by severity
        critical_alerts = Alert.query.filter_by(
            user_id=current_user.id,
            severity=VulnerabilitySeverity.CRITICAL,
            status=AlertStatus.OPEN
        ).count()
        
        high_alerts = Alert.query.filter_by(
            user_id=current_user.id,
            severity=VulnerabilitySeverity.HIGH,
            status=AlertStatus.OPEN
        ).count()
        
        # Recent alerts
        recent_alerts = Alert.query.filter_by(user_id=current_user.id).order_by(
            Alert.created_at.desc()
        ).limit(5).all()
        
        return jsonify({
            'alerts_summary': {
                'total': total_alerts,
                'open': open_alerts,
                'acknowledged': acknowledged_alerts,
                'resolved': resolved_alerts,
                'critical_open': critical_alerts,
                'high_open': high_alerts,
                'recent': [alert.to_dict() for alert in recent_alerts]
            }
        }), 200
        
    except Exception as e:
        logger.error("Alerts summary API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@dashboard_bp.route('/compliance/status', methods=['GET'])
@login_required
def api_compliance_status():
    """
    Get compliance status overview
    """
    try:
        # Calculate compliance scores based on vulnerabilities
        total_vulns = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.remediated == False
        ).count()
        
        critical_vulns = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.severity == VulnerabilitySeverity.CRITICAL,
            Vulnerability.remediated == False
        ).count()
        
        high_vulns = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.severity == VulnerabilitySeverity.HIGH,
            Vulnerability.remediated == False
        ).count()
        
        # Simplified compliance scoring
        compliance_standards = {
            'ISO27001': {
                'score': max(0, 100 - (critical_vulns * 20) - (high_vulns * 10)),
                'status': 'Non-Compliant' if critical_vulns > 0 else 'Compliant',
                'issues': critical_vulns + high_vulns
            },
            'SOC2': {
                'score': max(0, 100 - (critical_vulns * 25) - (high_vulns * 8)),
                'status': 'Non-Compliant' if critical_vulns > 0 else 'Compliant',
                'issues': critical_vulns + high_vulns
            },
            'GDPR': {
                'score': max(0, 100 - (critical_vulns * 30) - (high_vulns * 12)),
                'status': 'Non-Compliant' if critical_vulns > 0 else 'Compliant',
                'issues': critical_vulns + high_vulns
            },
            'NIST': {
                'score': max(0, 100 - (critical_vulns * 15) - (high_vulns * 7)),
                'status': 'Non-Compliant' if critical_vulns > 0 else 'Compliant',
                'issues': critical_vulns + high_vulns
            }
        }
        
        overall_score = sum(standard['score'] for standard in compliance_standards.values()) / len(compliance_standards)
        
        return jsonify({
            'compliance_status': {
                'overall_score': round(overall_score, 1),
                'standards': compliance_standards,
                'last_assessment': datetime.now(timezone.utc).isoformat(),
                'next_review': (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error("Compliance status API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

def calculate_risk_score(critical: int, high: int, medium: int, low: int) -> dict:
    """
    Calculate risk score based on vulnerability counts
    """
    # Weighted risk calculation
    weighted_score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
    
    # Normalize to 0-100 scale
    max_score = 100
    normalized_score = min(weighted_score, max_score)
    
    # Determine risk level
    if normalized_score >= 80:
        risk_level = 'Critical'
        color = '#dc3545'
    elif normalized_score >= 60:
        risk_level = 'High'
        color = '#fd7e14'
    elif normalized_score >= 40:
        risk_level = 'Medium'
        color = '#ffc107'
    elif normalized_score >= 20:
        risk_level = 'Low'
        color = '#28a745'
    else:
        risk_level = 'Minimal'
        color = '#6c757d'
    
    return {
        'score': normalized_score,
        'level': risk_level,
        'color': color,
        'components': {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low
        }
    }

