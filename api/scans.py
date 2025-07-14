# JADE Ultimate - Scans API
# Security scan management endpoints

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timezone
import structlog

from app import db, limiter
from models import Scan, Vulnerability, ScanStatus, VulnerabilitySeverity
from utils.security import requires_role, validate_target, validate_scan_config, check_rate_limit
from utils.logger import get_security_logger
from services.scanner_service import ScannerService

logger = structlog.get_logger()
security_logger = get_security_logger()

scans_bp = Blueprint('scans', __name__)
scanner_service = ScannerService()

@scans_bp.route('', methods=['GET'])
@login_required
def api_list_scans():
    """
    List user's scans with filtering and pagination
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Build query
        scans_query = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc())
        
        # Apply filters
        status_filter = request.args.get('status')
        if status_filter:
            try:
                status_enum = ScanStatus(status_filter)
                scans_query = scans_query.filter_by(status=status_enum)
            except ValueError:
                return jsonify({'error': f'Invalid status: {status_filter}'}), 400
        
        scan_type_filter = request.args.get('scan_type')
        if scan_type_filter:
            scans_query = scans_query.filter_by(scan_type=scan_type_filter)
        
        # Date range filter
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                scans_query = scans_query.filter(Scan.created_at >= start_dt)
            except ValueError:
                return jsonify({'error': 'Invalid start_date format'}), 400
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date)
                scans_query = scans_query.filter(Scan.created_at <= end_dt)
            except ValueError:
                return jsonify({'error': 'Invalid end_date format'}), 400
        
        # Paginate
        pagination = scans_query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        scans_data = []
        for scan in pagination.items:
            scans_data.append(scan.to_dict())
        
        return jsonify({
            'scans': scans_data,
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
        logger.error("List scans API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('', methods=['POST'])
@login_required
@requires_role(['admin', 'analyst'])
@limiter.limit("10 per hour")
def api_create_scan():
    """
    Create a new security scan
    """
    try:
        # Check rate limit
        if not check_rate_limit(current_user.id, 'create_scan', 10, 3600):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['name', 'scan_type', 'target']
        for field in required_fields:
            if not data.get(field, '').strip():
                return jsonify({'error': f'{field} is required'}), 400
        
        name = data['name'].strip()
        description = data.get('description', '').strip()
        scan_type = data['scan_type'].strip()
        target = data['target'].strip()
        scan_options = data.get('scan_options', {})
        
        # Validate scan type
        valid_scan_types = ['network', 'web', 'ssl', 'infrastructure']
        if scan_type not in valid_scan_types:
            return jsonify({'error': f'Invalid scan type. Valid types: {valid_scan_types}'}), 400
        
        # Validate target
        if not validate_target(target, scan_type):
            return jsonify({'error': 'Invalid target format for selected scan type'}), 400
        
        # Validate scan configuration
        valid_config, config_error = validate_scan_config(scan_options, scan_type)
        if not valid_config:
            return jsonify({'error': f'Invalid scan configuration: {config_error}'}), 400
        
        # Check if user has reached scan limit
        active_scans = Scan.query.filter_by(
            user_id=current_user.id,
            status=ScanStatus.RUNNING
        ).count()
        
        if active_scans >= 5:  # Limit concurrent scans
            return jsonify({'error': 'Maximum concurrent scans limit reached (5)'}), 429
        
        # Create scan
        scan = Scan(
            name=name,
            description=description,
            scan_type=scan_type,
            target=target,
            scan_options=scan_options,
            status=ScanStatus.PENDING,
            user_id=current_user.id
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Queue scan for execution
        try:
            from tasks import process_scan_task
            process_scan_task.delay(scan.id)
            
            logger.info("Scan created and queued", 
                       scan_id=scan.id, 
                       user_id=current_user.id,
                       scan_type=scan_type,
                       target=target)
            
            security_logger.log_data_access(
                current_user.id, 'scan', scan.id, 'create'
            )
            
            return jsonify({
                'message': 'Scan created successfully',
                'scan': scan.to_dict()
            }), 201
            
        except Exception as e:
            logger.error("Failed to queue scan", scan_id=scan.id, error=str(e))
            scan.status = ScanStatus.FAILED
            scan.error_message = "Failed to queue scan for processing"
            db.session.commit()
            
            return jsonify({
                'message': 'Scan created but failed to queue',
                'scan': scan.to_dict()
            }), 201
        
    except Exception as e:
        logger.error("Create scan API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/<int:scan_id>', methods=['GET'])
@login_required
def api_get_scan(scan_id):
    """
    Get scan details
    """
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Include vulnerabilities in response
        scan_data = scan.to_dict()
        
        # Get vulnerabilities
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).order_by(
            Vulnerability.severity.desc(),
            Vulnerability.created_at.desc()
        ).all()
        
        scan_data['vulnerabilities'] = [vuln.to_dict() for vuln in vulnerabilities]
        
        security_logger.log_data_access(
            current_user.id, 'scan', scan.id, 'read'
        )
        
        return jsonify({'scan': scan_data}), 200
        
    except Exception as e:
        logger.error("Get scan API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/<int:scan_id>', methods=['PUT'])
@login_required
@requires_role(['admin', 'analyst'])
def api_update_scan(scan_id):
    """
    Update scan details
    """
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Can only update pending or failed scans
        if scan.status not in [ScanStatus.PENDING, ScanStatus.FAILED]:
            return jsonify({'error': 'Cannot update scan in current status'}), 400
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update allowed fields
        if 'name' in data:
            name = data['name'].strip()
            if not name:
                return jsonify({'error': 'Name cannot be empty'}), 400
            scan.name = name
        
        if 'description' in data:
            scan.description = data['description'].strip()
        
        if 'scan_options' in data:
            scan_options = data['scan_options']
            
            # Validate new configuration
            valid_config, config_error = validate_scan_config(scan_options, scan.scan_type)
            if not valid_config:
                return jsonify({'error': f'Invalid scan configuration: {config_error}'}), 400
            
            scan.scan_options = scan_options
        
        scan.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        logger.info("Scan updated", scan_id=scan.id, user_id=current_user.id)
        
        security_logger.log_data_access(
            current_user.id, 'scan', scan.id, 'update'
        )
        
        return jsonify({
            'message': 'Scan updated successfully',
            'scan': scan.to_dict()
        }), 200
        
    except Exception as e:
        logger.error("Update scan API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/<int:scan_id>', methods=['DELETE'])
@login_required
@requires_role(['admin', 'analyst'])
def api_delete_scan(scan_id):
    """
    Delete scan and related data
    """
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Cannot delete running scans
        if scan.status == ScanStatus.RUNNING:
            return jsonify({'error': 'Cannot delete running scan'}), 400
        
        # Delete related vulnerabilities first
        Vulnerability.query.filter_by(scan_id=scan.id).delete()
        
        # Delete scan
        db.session.delete(scan)
        db.session.commit()
        
        logger.info("Scan deleted", scan_id=scan.id, user_id=current_user.id)
        
        security_logger.log_data_access(
            current_user.id, 'scan', scan.id, 'delete'
        )
        
        return jsonify({'message': 'Scan deleted successfully'}), 200
        
    except Exception as e:
        logger.error("Delete scan API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/<int:scan_id>/cancel', methods=['POST'])
@login_required
@requires_role(['admin', 'analyst'])
def api_cancel_scan(scan_id):
    """
    Cancel running scan
    """
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != ScanStatus.RUNNING:
            return jsonify({'error': 'Scan is not running'}), 400
        
        # Update scan status
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.now(timezone.utc)
        if scan.started_at:
            scan.duration = int((scan.completed_at - scan.started_at).total_seconds())
        scan.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        logger.info("Scan cancelled", scan_id=scan.id, user_id=current_user.id)
        
        return jsonify({
            'message': 'Scan cancelled successfully',
            'scan': scan.to_dict()
        }), 200
        
    except Exception as e:
        logger.error("Cancel scan API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/<int:scan_id>/retry', methods=['POST'])
@login_required
@requires_role(['admin', 'analyst'])
def api_retry_scan(scan_id):
    """
    Retry failed scan
    """
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != ScanStatus.FAILED:
            return jsonify({'error': 'Can only retry failed scans'}), 400
        
        # Reset scan status
        scan.status = ScanStatus.PENDING
        scan.error_message = None
        scan.started_at = None
        scan.completed_at = None
        scan.duration = None
        scan.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        # Queue scan for retry
        try:
            from tasks import process_scan_task
            process_scan_task.delay(scan.id)
            
            logger.info("Scan retry queued", scan_id=scan.id, user_id=current_user.id)
            
            return jsonify({
                'message': 'Scan retry queued successfully',
                'scan': scan.to_dict()
            }), 200
            
        except Exception as e:
            logger.error("Failed to queue scan retry", scan_id=scan.id, error=str(e))
            scan.status = ScanStatus.FAILED
            scan.error_message = "Failed to queue scan for retry"
            db.session.commit()
            
            return jsonify({'error': 'Failed to queue scan retry'}), 500
        
    except Exception as e:
        logger.error("Retry scan API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/statistics', methods=['GET'])
@login_required
def api_scan_statistics():
    """
    Get scan statistics for current user
    """
    try:
        # Basic statistics
        total_scans = Scan.query.filter_by(user_id=current_user.id).count()
        completed_scans = Scan.query.filter_by(
            user_id=current_user.id, 
            status=ScanStatus.COMPLETED
        ).count()
        failed_scans = Scan.query.filter_by(
            user_id=current_user.id, 
            status=ScanStatus.FAILED
        ).count()
        running_scans = Scan.query.filter_by(
            user_id=current_user.id, 
            status=ScanStatus.RUNNING
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
        
        # Scan type distribution
        scan_types = db.session.query(
            Scan.scan_type,
            db.func.count(Scan.id).label('count')
        ).filter_by(user_id=current_user.id).group_by(Scan.scan_type).all()
        
        scan_type_distribution = {scan_type: count for scan_type, count in scan_types}
        
        return jsonify({
            'statistics': {
                'total_scans': total_scans,
                'completed_scans': completed_scans,
                'failed_scans': failed_scans,
                'running_scans': running_scans,
                'total_vulnerabilities': total_vulnerabilities,
                'critical_vulnerabilities': critical_vulns,
                'high_vulnerabilities': high_vulns,
                'scan_type_distribution': scan_type_distribution,
                'success_rate': (completed_scans / total_scans * 100) if total_scans > 0 else 0
            }
        }), 200
        
    except Exception as e:
        logger.error("Get scan statistics API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@scans_bp.route('/templates', methods=['GET'])
@login_required
def api_scan_templates():
    """
    Get scan templates and configurations
    """
    try:
        templates = {
            'network': {
                'name': 'Network Security Scan',
                'description': 'Comprehensive network security assessment',
                'default_options': {
                    'tcp_scan': True,
                    'service_detection': True,
                    'os_detection': False,
                    'script_scan': False,
                    'timing': 'normal'
                },
                'available_options': {
                    'tcp_scan': {'type': 'boolean', 'description': 'TCP port scanning'},
                    'udp_scan': {'type': 'boolean', 'description': 'UDP port scanning'},
                    'service_detection': {'type': 'boolean', 'description': 'Service version detection'},
                    'os_detection': {'type': 'boolean', 'description': 'Operating system detection'},
                    'script_scan': {'type': 'boolean', 'description': 'Run default NSE scripts'},
                    'timing': {
                        'type': 'select',
                        'options': ['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'],
                        'description': 'Scan timing template'
                    }
                }
            },
            'web': {
                'name': 'Web Application Scan',
                'description': 'Web application security assessment',
                'default_options': {
                    'ssl_scan': True,
                    'directory_scan': True,
                    'vulnerability_scan': True,
                    'crawl_depth': 2
                },
                'available_options': {
                    'ssl_scan': {'type': 'boolean', 'description': 'SSL/TLS configuration check'},
                    'directory_scan': {'type': 'boolean', 'description': 'Directory enumeration'},
                    'vulnerability_scan': {'type': 'boolean', 'description': 'Common vulnerability checks'},
                    'crawl_depth': {'type': 'number', 'min': 1, 'max': 5, 'description': 'Web crawling depth'}
                }
            },
            'ssl': {
                'name': 'SSL/TLS Security Scan',
                'description': 'SSL/TLS configuration and certificate analysis',
                'default_options': {
                    'certificate_check': True,
                    'cipher_analysis': True,
                    'protocol_check': True,
                    'vulnerability_check': True
                },
                'available_options': {
                    'certificate_check': {'type': 'boolean', 'description': 'Certificate validation'},
                    'cipher_analysis': {'type': 'boolean', 'description': 'Cipher suite analysis'},
                    'protocol_check': {'type': 'boolean', 'description': 'Protocol version check'},
                    'vulnerability_check': {'type': 'boolean', 'description': 'Known SSL vulnerabilities'}
                }
            },
            'infrastructure': {
                'name': 'Infrastructure Security Scan',
                'description': 'Infrastructure security assessment',
                'default_options': {
                    'service_enumeration': True,
                    'configuration_check': True,
                    'security_assessment': True
                },
                'available_options': {
                    'service_enumeration': {'type': 'boolean', 'description': 'Service enumeration'},
                    'configuration_check': {'type': 'boolean', 'description': 'Configuration analysis'},
                    'security_assessment': {'type': 'boolean', 'description': 'Security posture assessment'}
                }
            }
        }
        
        return jsonify({'templates': templates}), 200
        
    except Exception as e:
        logger.error("Get scan templates API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

