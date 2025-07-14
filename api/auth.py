# JADE Ultimate - Authentication API
# Authentication and user management endpoints

from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
from datetime import datetime, timezone, timedelta
import structlog

from app import db, limiter
from models import User, UserRole
from utils.security import validate_password_strength, validate_email, validate_username
from utils.encryption import create_jwt_token, verify_jwt_token, generate_secure_token
from utils.logger import get_security_logger

logger = structlog.get_logger()
security_logger = get_security_logger()

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    """
    API endpoint for user authentication
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        remember = data.get('remember', False)
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user:
            security_logger.log_authentication_attempt(
                username, request.remote_addr, False, "User not found"
            )
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is active
        if not user.is_active:
            security_logger.log_authentication_attempt(
                username, request.remote_addr, False, "Account disabled"
            )
            return jsonify({'error': 'Account is disabled'}), 401
        
        # Check for account lockout
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            return jsonify({'error': 'Account is temporarily locked'}), 401
        
        # Verify password
        if not user.check_password(password):
            # Update failed login attempts
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(hours=1)
            db.session.commit()
            
            security_logger.log_authentication_attempt(
                username, request.remote_addr, False, "Invalid password"
            )
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Successful login
        login_user(user, remember=remember)
        user.last_login = datetime.now(timezone.utc)
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        
        security_logger.log_authentication_attempt(
            username, request.remote_addr, True
        )
        
        # Create JWT token
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role.value,
            'full_name': user.full_name()
        }
        
        access_token = create_jwt_token(user.id, user_data, expires_in=1800)  # 30 minutes
        
        return jsonify({
            'message': 'Login successful',
            'user': user_data,
            'access_token': access_token
        }), 200
        
    except Exception as e:
        logger.error("Login API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def api_logout():
    """
    API endpoint for user logout
    """
    try:
        user_id = current_user.id
        logout_user()
        session.clear()
        
        logger.info("User logged out via API", user_id=user_id)
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        logger.error("Logout API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("3 per minute")
def api_register():
    """
    API endpoint for user registration (admin only)
    """
    try:
        if not current_user.is_authenticated or not current_user.is_admin():
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['username', 'email', 'first_name', 'last_name', 'password']
        for field in required_fields:
            if not data.get(field, '').strip():
                return jsonify({'error': f'{field} is required'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip()
        first_name = data['first_name'].strip()
        last_name = data['last_name'].strip()
        password = data['password']
        role = data.get('role', 'viewer')
        
        # Validate username
        valid_username, username_error = validate_username(username)
        if not valid_username:
            return jsonify({'error': username_error}), 400
        
        # Validate email
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password
        valid_password, password_errors = validate_password_strength(password)
        if not valid_password:
            return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
        
        # Validate role
        valid_roles = [role.value for role in UserRole]
        if role not in valid_roles:
            return jsonify({'error': f'Invalid role. Valid roles: {valid_roles}'}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 409
        
        # Create user
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            role=UserRole(role),
            is_active=True,
            is_verified=False
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        logger.info("User registered via API", 
                   user_id=user.id, 
                   admin_id=current_user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role.value
            }
        }), 201
        
    except Exception as e:
        logger.error("Registration API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/profile', methods=['GET'])
@login_required
def api_get_profile():
    """
    Get current user profile
    """
    try:
        user_data = {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'first_name': current_user.first_name,
            'last_name': current_user.last_name,
            'role': current_user.role.value,
            'is_active': current_user.is_active,
            'is_verified': current_user.is_verified,
            'last_login': current_user.last_login.isoformat() if current_user.last_login else None,
            'created_at': current_user.created_at.isoformat(),
            'two_factor_enabled': current_user.two_factor_enabled,
            'preferences': current_user.preferences or {}
        }
        
        return jsonify({'user': user_data}), 200
        
    except Exception as e:
        logger.error("Get profile API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/profile', methods=['PUT'])
@login_required
def api_update_profile():
    """
    Update current user profile
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update allowed fields
        if 'first_name' in data:
            first_name = data['first_name'].strip()
            if not first_name:
                return jsonify({'error': 'First name cannot be empty'}), 400
            current_user.first_name = first_name
        
        if 'last_name' in data:
            last_name = data['last_name'].strip()
            if not last_name:
                return jsonify({'error': 'Last name cannot be empty'}), 400
            current_user.last_name = last_name
        
        if 'email' in data:
            email = data['email'].strip()
            if not validate_email(email):
                return jsonify({'error': 'Invalid email format'}), 400
            
            # Check if email is already taken
            existing_user = User.query.filter_by(email=email).filter(User.id != current_user.id).first()
            if existing_user:
                return jsonify({'error': 'Email is already taken'}), 409
            
            current_user.email = email
        
        if 'preferences' in data:
            if isinstance(data['preferences'], dict):
                current_user.preferences = data['preferences']
        
        current_user.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        logger.info("Profile updated via API", user_id=current_user.id)
        
        return jsonify({'message': 'Profile updated successfully'}), 200
        
    except Exception as e:
        logger.error("Update profile API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def api_change_password():
    """
    Change user password
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        # Verify current password
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Validate new password
        valid_password, password_errors = validate_password_strength(new_password)
        if not valid_password:
            return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
        
        # Update password
        current_user.set_password(new_password)
        current_user.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        security_logger.log_security_event(
            'password_change', current_user.id, 'User changed password via API'
        )
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        logger.error("Change password API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/verify-token', methods=['POST'])
def api_verify_token():
    """
    Verify JWT token
    """
    try:
        data = request.get_json()
        
        if not data or 'token' not in data:
            return jsonify({'error': 'Token is required'}), 400
        
        token = data['token']
        
        # Verify token
        payload = verify_jwt_token(token)
        
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Get user data
        user_id = payload.get('user_id')
        user = User.query.get(user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'Invalid user'}), 401
        
        return jsonify({
            'valid': True,
            'user': payload.get('user_data', {}),
            'expires_at': payload.get('exp')
        }), 200
        
    except Exception as e:
        logger.error("Token verification API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/refresh-token', methods=['POST'])
@login_required
def api_refresh_token():
    """
    Refresh JWT token
    """
    try:
        user_data = {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'role': current_user.role.value,
            'full_name': current_user.full_name()
        }
        
        access_token = create_jwt_token(current_user.id, user_data, expires_in=1800)
        
        return jsonify({
            'access_token': access_token,
            'user': user_data
        }), 200
        
    except Exception as e:
        logger.error("Token refresh API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/users', methods=['GET'])
@login_required
def api_list_users():
    """
    List users (admin only)
    """
    try:
        if not current_user.is_admin():
            return jsonify({'error': 'Admin access required'}), 403
        
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        users_query = User.query.order_by(User.created_at.desc())
        
        # Apply filters
        role_filter = request.args.get('role')
        if role_filter:
            users_query = users_query.filter_by(role=role_filter)
        
        status_filter = request.args.get('status')
        if status_filter == 'active':
            users_query = users_query.filter_by(is_active=True)
        elif status_filter == 'inactive':
            users_query = users_query.filter_by(is_active=False)
        
        # Paginate
        pagination = users_query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        users_data = []
        for user in pagination.items:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name(),
                'role': user.role.value,
                'is_active': user.is_active,
                'is_verified': user.is_verified,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'created_at': user.created_at.isoformat()
            })
        
        return jsonify({
            'users': users_data,
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
        logger.error("List users API error", error=str(e))
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def api_toggle_user_status(user_id):
    """
    Toggle user active status (admin only)
    """
    try:
        if not current_user.is_admin():
            return jsonify({'error': 'Admin access required'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot deactivate your own account'}), 400
        
        user.is_active = not user.is_active
        user.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        action = 'activated' if user.is_active else 'deactivated'
        
        security_logger.log_security_event(
            'user_status_change', 
            current_user.id, 
            f'User {user.username} {action} by admin {current_user.username}',
            'info'
        )
        
        return jsonify({
            'message': f'User {user.username} has been {action}',
            'user': {
                'id': user.id,
                'username': user.username,
                'is_active': user.is_active
            }
        }), 200
        
    except Exception as e:
        logger.error("Toggle user status API error", error=str(e))
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

