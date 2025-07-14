# JADE Ultimate - Reports API
# Report generation and management endpoints

from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from datetime import datetime, timezone
import os
import structlog

from app import db, limiter
from models import Report, Scan, Vulnerability
from utils.security import requires_role
from utils.logger import get_security_logger
from services.report_service import ReportService

logger = structlog.get_logger()
security_logger = get_security_logger()

reports_bp = Blueprint('reports', __name__)
report_service = ReportService()

@reports_bp.route('', methods=['GET'])
@login_required
def api_list_reports():
    """
    List user's reports with filtering and pagination
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Build query
        reports_query = Report.query.filter_by(user_id=current_user.id).order_by(
            Report.created_at.desc()
        )
        
        # Apply filters
        report_type_filter = request.args.get('report_type')
        if report_type_filter:
            valid_types = ['executive', 'technical', 'compliance', 'vulnerability']
            if report_type_filter in valid_types:
                reports_query = reports_query.filter_by(report_type=report_type_filter)
        
        format_filter = request.args.get('format')
        if format_filter:
            valid_formats = ['html', 'pdf', 'json']
            if format_filter in valid_formats:
                reports_query = reports_query.filter_by(format=format_filter)
        
        # Date range filter
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                reports_query = reports_query.filter(Report.created_at >= start_dt)
            except ValueError:
                return jsonify({'error': 'Invalid start_date format'}), 400
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date)
                reports_query = reports_query.filter(Report.created_at <= end_dt)
            except ValueError:
                return jsonify({'error': 'Invalid end_date format'}), 400
        
        # Paginate
        pagination = reports_query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        reports_data = []
        for report in pagination.items:
            report_dict = report.to_dict()
            
            # Add scan information if linked
            if report.scan_id:
                scan = Scan.query.get(report.scan_id)
                if scan:
                    report_dict['scan'] = {
                        'id': scan.id,
                        'name': scan.name,
                        'scan_type': scan.scan_type,
                        'target': scan.target
                    }
            
            reports_data.append(report_dict)
        
        return jsonify({
            'reports': reports_data,
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
        logger.error("List reports API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('', methods=['POST'])
@login_required
@requires_role(['admin', 'analyst'])
@limiter.limit("5 per hour")
def api_create_report():
    """
    Create a new report
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['title', 'report_type']
        for field in required_fields:
            if not data.get(field, '').strip():
                return jsonify({'error': f'{field} is required'}), 400
        
        title = data['title'].strip()
        description = data.get('description', '').strip()
        report_type = data['report_type'].strip()
        scan_id = data.get('scan_id')
        format_type = data.get('format', 'html')
        
        # Validate report type
        valid_types = ['executive', 'technical', 'compliance', 'vulnerability']
        if report_type not in valid_types:
            return jsonify({'error': f'Invalid report type. Valid types: {valid_types}'}), 400
        
        # Validate format
        valid_formats = ['html', 'pdf', 'json']
        if format_type not in valid_formats:
            return jsonify({'error': f'Invalid format. Valid formats: {valid_formats}'}), 400
        
        # Validate scan if provided
        if scan_id:
            scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
            if not scan:
                return jsonify({'error': 'Invalid scan ID or scan not accessible'}), 400
        
        # Create report
        report = Report(
            title=title,
            description=description,
            report_type=report_type,
            format=format_type,
            scan_id=scan_id,
            user_id=current_user.id
        )
        
        db.session.add(report)
        db.session.commit()
        
        # Queue report generation
        try:
            from tasks import generate_report_task
            generate_report_task.delay(report.id)
            
            logger.info("Report created and queued", 
                       report_id=report.id, 
                       user_id=current_user.id,
                       report_type=report_type)
            
            security_logger.log_data_access(
                current_user.id, 'report', report.id, 'create'
            )
            
            return jsonify({
                'message': 'Report created successfully',
                'report': report.to_dict()
            }), 201
            
        except Exception as e:
            logger.error("Failed to queue report generation", report_id=report.id, error=str(e))
            
            return jsonify({
                'message': 'Report created but generation failed to queue',
                'report': report.to_dict()
            }), 201
        
    except Exception as e:
        logger.error("Create report API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('/<int:report_id>', methods=['GET'])
@login_required
def api_get_report(report_id):
    """
    Get report details
    """
    try:
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        report_data = report.to_dict()
        
        # Add scan information if linked
        if report.scan_id:
            scan = Scan.query.get(report.scan_id)
            if scan:
                report_data['scan'] = {
                    'id': scan.id,
                    'name': scan.name,
                    'scan_type': scan.scan_type,
                    'target': scan.target,
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
                }
        
        security_logger.log_data_access(
            current_user.id, 'report', report.id, 'read'
        )
        
        return jsonify({'report': report_data}), 200
        
    except Exception as e:
        logger.error("Get report API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('/<int:report_id>', methods=['DELETE'])
@login_required
@requires_role(['admin', 'analyst'])
def api_delete_report(report_id):
    """
    Delete report
    """
    try:
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        # Delete associated file if exists
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
            except Exception as e:
                logger.warning("Failed to delete report file", file_path=report.file_path, error=str(e))
        
        # Delete report from database
        db.session.delete(report)
        db.session.commit()
        
        logger.info("Report deleted", report_id=report.id, user_id=current_user.id)
        
        security_logger.log_data_access(
            current_user.id, 'report', report.id, 'delete'
        )
        
        return jsonify({'message': 'Report deleted successfully'}), 200
        
    except Exception as e:
        logger.error("Delete report API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('/<int:report_id>/download', methods=['GET'])
@login_required
def api_download_report(report_id):
    """
    Download report file
    """
    try:
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        if not report.file_path or not os.path.exists(report.file_path):
            return jsonify({'error': 'Report file not available'}), 404
        
        # Log download
        security_logger.log_data_access(
            current_user.id, 'report', report.id, 'download'
        )
        
        # Determine content type
        content_type = 'application/pdf' if report.format == 'pdf' else 'text/html'
        
        return send_file(
            report.file_path,
            as_attachment=True,
            download_name=f"{report.title.replace(' ', '_')}.{report.format}",
            mimetype=content_type
        )
        
    except Exception as e:
        logger.error("Download report API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('/<int:report_id>/regenerate', methods=['POST'])
@login_required
@requires_role(['admin', 'analyst'])
def api_regenerate_report(report_id):
    """
    Regenerate report
    """
    try:
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        # Reset report content and file
        report.content = {}
        report.generation_time = None
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
            except Exception:
                pass
        report.file_path = None
        report.file_size = None
        report.file_hash = None
        
        db.session.commit()
        
        # Queue report generation
        try:
            from tasks import generate_report_task
            generate_report_task.delay(report.id)
            
            logger.info("Report regeneration queued", 
                       report_id=report.id, 
                       user_id=current_user.id)
            
            return jsonify({
                'message': 'Report regeneration queued successfully',
                'report': report.to_dict()
            }), 200
            
        except Exception as e:
            logger.error("Failed to queue report regeneration", report_id=report.id, error=str(e))
            return jsonify({'error': 'Failed to queue report regeneration'}), 500
        
    except Exception as e:
        logger.error("Regenerate report API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('/templates', methods=['GET'])
@login_required
def api_report_templates():
    """
    Get available report templates
    """
    try:
        templates = {
            'executive': {
                'name': 'Executive Summary Report',
                'description': 'High-level security overview for executives and management',
                'sections': [
                    'Executive Summary',
                    'Risk Assessment',
                    'Key Findings',
                    'Business Impact',
                    'Recommendations',
                    'Compliance Status'
                ],
                'audience': 'Executives, Management',
                'technical_level': 'Low'
            },
            'technical': {
                'name': 'Technical Security Report',
                'description': 'Detailed technical analysis for security teams',
                'sections': [
                    'Methodology',
                    'Network Topology',
                    'Vulnerability Details',
                    'Proof of Concept',
                    'Remediation Guide',
                    'Technical Appendices'
                ],
                'audience': 'Security Engineers, IT Teams',
                'technical_level': 'High'
            },
            'compliance': {
                'name': 'Compliance Report',
                'description': 'Compliance assessment and audit findings',
                'sections': [
                    'Compliance Overview',
                    'Regulatory Requirements',
                    'Compliance Gaps',
                    'Remediation Priorities',
                    'Audit Trail',
                    'Certification Status'
                ],
                'audience': 'Compliance Officers, Auditors',
                'technical_level': 'Medium'
            },
            'vulnerability': {
                'name': 'Vulnerability Assessment Report',
                'description': 'Comprehensive vulnerability analysis and remediation plan',
                'sections': [
                    'Vulnerability Summary',
                    'Severity Analysis',
                    'Vulnerability Categories',
                    'Exploitation Analysis',
                    'Remediation Roadmap',
                    'Risk Matrix'
                ],
                'audience': 'Security Teams, Developers',
                'technical_level': 'High'
            }
        }
        
        return jsonify({'templates': templates}), 200
        
    except Exception as e:
        logger.error("Get report templates API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('/statistics', methods=['GET'])
@login_required
def api_report_statistics():
    """
    Get report statistics for current user
    """
    try:
        # Basic statistics
        total_reports = Report.query.filter_by(user_id=current_user.id).count()
        
        # Report type distribution
        type_stats = db.session.query(
            Report.report_type,
            db.func.count(Report.id).label('count')
        ).filter_by(user_id=current_user.id).group_by(Report.report_type).all()
        
        type_distribution = {report_type: count for report_type, count in type_stats}
        
        # Format distribution
        format_stats = db.session.query(
            Report.format,
            db.func.count(Report.id).label('count')
        ).filter_by(user_id=current_user.id).group_by(Report.format).all()
        
        format_distribution = {format_type: count for format_type, count in format_stats}
        
        # AI-generated reports
        ai_generated_count = Report.query.filter_by(
            user_id=current_user.id,
            ai_generated=True
        ).count()
        
        # Recent reports (last 30 days)
        from datetime import timedelta
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        recent_reports = Report.query.filter(
            Report.user_id == current_user.id,
            Report.created_at >= thirty_days_ago
        ).count()
        
        # Average generation time
        avg_generation_time = db.session.query(
            db.func.avg(Report.generation_time)
        ).filter_by(user_id=current_user.id).scalar()
        
        return jsonify({
            'statistics': {
                'total_reports': total_reports,
                'type_distribution': type_distribution,
                'format_distribution': format_distribution,
                'ai_generated_count': ai_generated_count,
                'recent_reports': recent_reports,
                'avg_generation_time': round(avg_generation_time, 2) if avg_generation_time else 0,
                'ai_usage_rate': (ai_generated_count / total_reports * 100) if total_reports > 0 else 0
            }
        }), 200
        
    except Exception as e:
        logger.error("Get report statistics API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('/preview', methods=['POST'])
@login_required
@requires_role(['admin', 'analyst'])
def api_preview_report():
    """
    Generate report preview without saving
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        report_type = data.get('report_type')
        scan_id = data.get('scan_id')
        
        if not report_type:
            return jsonify({'error': 'report_type is required'}), 400
        
        # Validate report type
        valid_types = ['executive', 'technical', 'compliance', 'vulnerability']
        if report_type not in valid_types:
            return jsonify({'error': f'Invalid report type. Valid types: {valid_types}'}), 400
        
        # Get scan data if provided
        scan_data = None
        if scan_id:
            scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
            if not scan:
                return jsonify({'error': 'Invalid scan ID or scan not accessible'}), 400
            scan_data = scan.to_dict()
            
            # Get vulnerabilities
            vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()
            scan_data['vulnerabilities'] = [v.to_dict() for v in vulnerabilities]
        
        # Generate preview using report service
        from services.report_service import ReportContext
        
        context = ReportContext(
            title=f"Preview Report - {report_type.title()}",
            description="Report preview",
            report_type=report_type,
            scan_data=scan_data,
            vulnerabilities=scan_data.get('vulnerabilities', []) if scan_data else []
        )
        
        # Generate preview content (simplified)
        if report_type == 'executive':
            preview_content = report_service._generate_template_executive_report(context)
        elif report_type == 'technical':
            preview_content = report_service._generate_template_technical_report(context)
        elif report_type == 'compliance':
            preview_content = await report_service._generate_compliance_report(context, None)
        else:  # vulnerability
            preview_content = await report_service._generate_vulnerability_report(context, None)
        
        return jsonify({
            'preview': preview_content,
            'report_type': report_type,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error("Report preview API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

