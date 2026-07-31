from flask import Blueprint, jsonify
from models import User
from routes.auth import token_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/api/admin/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    # Planted Vulnerability: BFLA (Broken Function Level Authorization)
    # The endpoint relies on token_required to authenticate the user, but does NOT
    # perform any authorization check (e.g. current_user.is_admin or current_user.role == 'admin')
    # to restrict access to administrators only.
    
    users = User.query.all()
    return jsonify([u.to_dict() for u in users]), 200
