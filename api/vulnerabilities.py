# JADE Ultimate - Vulnerabilities API
# Vulnerability management endpoints

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timezone
import structlog

from app import db
from models import Vulnerability, Scan, VulnerabilitySeverity
from utils.security import requires_role
from utils.logger import get_security_logger
from services.ai_service import AIService

logger = structlog.get_logger()
security_logger = get_security_logger()

vulnerabilities_bp = Blueprint('vulnerabilities', __name__)
ai_service = AIService()

@vulnerabilities_bp.route('', methods=['GET'])
@login_required
def api_list_vulnerabilities():
    """
    List vulnerabilities with filtering and pagination
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Build query - only vulnerabilities from user's scans
        vulnerabilities_query = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id
        ).order_by(
            Vulnerability.severity.desc(),
            Vulnerability.created_at.desc()
        )
        
        # Apply filters
        severity_filter = request.args.get('severity')
        if severity_filter:
            try:
                severity_enum = VulnerabilitySeverity(severity_filter)
                vulnerabilities_query = vulnerabilities_query.filter(
                    Vulnerability.severity == severity_enum
                )
            except ValueError:
                return jsonify({'error': f'Invalid severity: {severity_filter}'}), 400
        
        status_filter = request.args.get('status')
        if status_filter:
            vulnerabilities_query = vulnerabilities_query.filter_by(status=status_filter)
        
        category_filter = request.args.get('category')
        if category_filter:
            vulnerabilities_query = vulnerabilities_query.filter_by(category=category_filter)
        
        # Search filter
        search = request.args.get('search')
        if search:
            search_term = f"%{search}%"
            vulnerabilities_query = vulnerabilities_query.filter(
                db.or_(
                    Vulnerability.title.ilike(search_term),
                    Vulnerability.description.ilike(search_term),
                    Vulnerability.target_host.ilike(search_term)
                )
            )
        
        # CVE filter
        cve_filter = request.args.get('cve')
        if cve_filter:
            vulnerabilities_query = vulnerabilities_query.filter_by(cve_id=cve_filter)
        
        # Date range filter
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                vulnerabilities_query = vulnerabilities_query.filter(
                    Vulnerability.created_at >= start_dt
                )
            except ValueError:
                return jsonify({'error': 'Invalid start_date format'}), 400
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date)
                vulnerabilities_query = vulnerabilities_query.filter(
                    Vulnerability.created_at <= end_dt
                )
            except ValueError:
                return jsonify({'error': 'Invalid end_date format'}), 400
        
        # Paginate
        pagination = vulnerabilities_query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        vulnerabilities_data = []
        for vuln in pagination.items:
            vuln_dict = vuln.to_dict()
            # Add scan information
            vuln_dict['scan'] = {
                'id': vuln.scan.id,
                'name': vuln.scan.name,
                'scan_type': vuln.scan.scan_type
            }
            vulnerabilities_data.append(vuln_dict)
        
        return jsonify({
            'vulnerabilities': vulnerabilities_data,
            'pagination': {
                'page': pagination.page,
                'per_page': pagination.per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        logger.error("List vulnerabilities API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@vulnerabilities_bp.route('/<int:vuln_id>', methods=['GET'])
@login_required
def api_get_vulnerability(vuln_id):
    """
    Get vulnerability details
    """
    try:
        vulnerability = db.session.query(Vulnerability).join(Scan).filter(
            Vulnerability.id == vuln_id,
            Scan.user_id == current_user.id
        ).first()
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        vuln_data = vulnerability.to_dict()
        
        # Add scan information
        vuln_data['scan'] = {
            'id': vulnerability.scan.id,
            'name': vulnerability.scan.name,
            'scan_type': vulnerability.scan.scan_type,
            'target': vulnerability.scan.target
        }
        
        security_logger.log_data_access(
            current_user.id, 'vulnerability', vulnerability.id, 'read'
        )
        
        return jsonify({'vulnerability': vuln_data}), 200
        
    except Exception as e:
        logger.error("Get vulnerability API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@vulnerabilities_bp.route('/<int:vuln_id>', methods=['PUT'])
@login_required
@requires_role(['admin', 'analyst'])
def api_update_vulnerability(vuln_id):
    """
    Update vulnerability details
    """
    try:
        vulnerability = db.session.query(Vulnerability).join(Scan).filter(
            Vulnerability.id == vuln_id,
            Scan.user_id == current_user.id
        ).first()
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update allowed fields
        if 'status' in data:
            valid_statuses = ['open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk']
            if data['status'] not in valid_statuses:
                return jsonify({'error': f'Invalid status. Valid statuses: {valid_statuses}'}), 400
            vulnerability.status = data['status']
        
        if 'false_positive' in data:
            vulnerability.false_positive = bool(data['false_positive'])
        
        if 'remediated' in data:
            vulnerability.remediated = bool(data['remediated'])
            if vulnerability.remediated and not vulnerability.remediation_date:
                vulnerability.remediation_date = datetime.now(timezone.utc)
        
        if 'remediation_notes' in data:
            vulnerability.remediation_notes = data['remediation_notes']
        
        if 'recommendation' in data:
            vulnerability.recommendation = data['recommendation']
        
        vulnerability.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        logger.info("Vulnerability updated", vuln_id=vulnerability.id, user_id=current_user.id)
        
        security_logger.log_data_access(
            current_user.id, 'vulnerability', vulnerability.id, 'update'
        )
        
        return jsonify({
            'message': 'Vulnerability updated successfully',
            'vulnerability': vulnerability.to_dict()
        }), 200
        
    except Exception as e:
        logger.error("Update vulnerability API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@vulnerabilities_bp.route('/<int:vuln_id>/analyze', methods=['POST'])
@login_required
@requires_role(['admin', 'analyst'])
def api_analyze_vulnerability(vuln_id):
    """
    Perform AI analysis on vulnerability
    """
    try:
        vulnerability = db.session.query(Vulnerability).join(Scan).filter(
            Vulnerability.id == vuln_id,
            Scan.user_id == current_user.id
        ).first()
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        # Prepare vulnerability data for AI analysis
        vuln_data = vulnerability.to_dict()
        
        # Perform AI analysis
        ai_response = await ai_service.analyze_vulnerability(vuln_data)
        
        if ai_response.content:
            # Update vulnerability with AI analysis
            vulnerability.ai_analysis = ai_response.metadata.get('analysis', {})
            vulnerability.ai_confidence = ai_response.confidence
            vulnerability.updated_at = datetime.now(timezone.utc)
            
            db.session.commit()
            
            logger.info("AI analysis completed for vulnerability", 
                       vuln_id=vulnerability.id, 
                       model=ai_response.model)
            
            return jsonify({
                'message': 'AI analysis completed successfully',
                'analysis': vulnerability.ai_analysis,
                'confidence': vulnerability.ai_confidence,
                'model_used': ai_response.model
            }), 200
        else:
            return jsonify({'error': 'AI analysis failed'}), 500
        
    except Exception as e:
        logger.error("AI vulnerability analysis API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@vulnerabilities_bp.route('/statistics', methods=['GET'])
@login_required
def api_vulnerability_statistics():
    """
    Get vulnerability statistics for current user
    """
    try:
        # Basic statistics
        total_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id
        ).count()
        
        # Severity distribution
        severity_stats = db.session.query(
            Vulnerability.severity,
            db.func.count(Vulnerability.id).label('count')
        ).join(Scan).filter(
            Scan.user_id == current_user.id
        ).group_by(Vulnerability.severity).all()
        
        severity_distribution = {
            severity.value: count for severity, count in severity_stats
        }
        
        # Status distribution
        status_stats = db.session.query(
            Vulnerability.status,
            db.func.count(Vulnerability.id).label('count')
        ).join(Scan).filter(
            Scan.user_id == current_user.id
        ).group_by(Vulnerability.status).all()
        
        status_distribution = {status: count for status, count in status_stats}
        
        # Category distribution
        category_stats = db.session.query(
            Vulnerability.category,
            db.func.count(Vulnerability.id).label('count')
        ).join(Scan).filter(
            Scan.user_id == current_user.id
        ).group_by(Vulnerability.category).all()
        
        category_distribution = {category: count for category, count in category_stats}
        
        # Remediation statistics
        remediated_count = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.remediated == True
        ).count()
        
        false_positive_count = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.false_positive == True
        ).count()
        
        # Recent vulnerabilities (last 30 days)
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        recent_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id,
            Vulnerability.created_at >= thirty_days_ago
        ).count()
        
        # Top categories
        top_categories = db.session.query(
            Vulnerability.category,
            db.func.count(Vulnerability.id).label('count')
        ).join(Scan).filter(
            Scan.user_id == current_user.id
        ).group_by(Vulnerability.category).order_by(
            db.func.count(Vulnerability.id).desc()
        ).limit(5).all()
        
        return jsonify({
            'statistics': {
                'total_vulnerabilities': total_vulnerabilities,
                'severity_distribution': severity_distribution,
                'status_distribution': status_distribution,
                'category_distribution': category_distribution,
                'remediated_count': remediated_count,
                'false_positive_count': false_positive_count,
                'recent_vulnerabilities': recent_vulnerabilities,
                'top_categories': [{'category': cat, 'count': count} for cat, count in top_categories],
                'remediation_rate': (remediated_count / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0
            }
        }), 200
        
    except Exception as e:
        logger.error("Get vulnerability statistics API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@vulnerabilities_bp.route('/export', methods=['GET'])
@login_required
def api_export_vulnerabilities():
    """
    Export vulnerabilities to CSV
    """
    try:
        # Get vulnerabilities for current user
        vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
            Scan.user_id == current_user.id
        ).order_by(
            Vulnerability.severity.desc(),
            Vulnerability.created_at.desc()
        ).all()
        
        # Apply filters if provided
        severity_filter = request.args.get('severity')
        if severity_filter:
            try:
                severity_enum = VulnerabilitySeverity(severity_filter)
                vulnerabilities = [v for v in vulnerabilities if v.severity == severity_enum]
            except ValueError:
                pass
        
        status_filter = request.args.get('status')
        if status_filter:
            vulnerabilities = [v for v in vulnerabilities if v.status == status_filter]
        
        # Generate CSV content
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'ID', 'Title', 'Severity', 'Category', 'CVE ID', 'CVSS Score',
            'Target Host', 'Target Port', 'Status', 'Remediated', 'False Positive',
            'Created At', 'Scan Name', 'Scan Type'
        ])
        
        # Write data
        for vuln in vulnerabilities:
            writer.writerow([
                vuln.id,
                vuln.title,
                vuln.severity.value,
                vuln.category,
                vuln.cve_id or '',
                vuln.cvss_score or '',
                vuln.target_host or '',
                vuln.target_port or '',
                vuln.status,
                vuln.remediated,
                vuln.false_positive,
                vuln.created_at.isoformat(),
                vuln.scan.name,
                vuln.scan.scan_type
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        logger.info("Vulnerabilities exported", 
                   user_id=current_user.id, 
                   count=len(vulnerabilities))
        
        return jsonify({
            'csv_content': csv_content,
            'filename': f'vulnerabilities_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            'count': len(vulnerabilities)
        }), 200
        
    except Exception as e:
        logger.error("Export vulnerabilities API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@vulnerabilities_bp.route('/bulk-update', methods=['POST'])
@login_required
@requires_role(['admin', 'analyst'])
def api_bulk_update_vulnerabilities():
    """
    Bulk update vulnerabilities
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        vulnerability_ids = data.get('vulnerability_ids', [])
        updates = data.get('updates', {})
        
        if not vulnerability_ids or not updates:
            return jsonify({'error': 'vulnerability_ids and updates are required'}), 400
        
        # Validate vulnerability IDs belong to user
        vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
            Vulnerability.id.in_(vulnerability_ids),
            Scan.user_id == current_user.id
        ).all()
        
        if len(vulnerabilities) != len(vulnerability_ids):
            return jsonify({'error': 'Some vulnerabilities not found or not accessible'}), 404
        
        # Apply updates
        updated_count = 0
        for vulnerability in vulnerabilities:
            if 'status' in updates:
                vulnerability.status = updates['status']
            
            if 'false_positive' in updates:
                vulnerability.false_positive = bool(updates['false_positive'])
            
            if 'remediated' in updates:
                vulnerability.remediated = bool(updates['remediated'])
                if vulnerability.remediated and not vulnerability.remediation_date:
                    vulnerability.remediation_date = datetime.now(timezone.utc)
            
            vulnerability.updated_at = datetime.now(timezone.utc)
            updated_count += 1
        
        db.session.commit()
        
        logger.info("Bulk vulnerability update", 
                   user_id=current_user.id, 
                   count=updated_count)
        
        security_logger.log_security_event(
            'bulk_vulnerability_update',
            current_user.id,
            f'Bulk updated {updated_count} vulnerabilities',
            'info'
        )
        
        return jsonify({
            'message': f'Successfully updated {updated_count} vulnerabilities',
            'updated_count': updated_count
        }), 200
        
    except Exception as e:
        logger.error("Bulk update vulnerabilities API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

