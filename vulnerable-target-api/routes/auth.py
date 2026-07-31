import hashlib
import jwt
from flask import Blueprint, request, jsonify, current_app
from functools import wraps
from models import db, User

auth_bp = Blueprint('auth', __name__)

JWT_SECRET = "secret"  # Intentionally weak/guessable secret

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        
        try:
            # Planted JWT Vulnerability: Support alg="none"
            unverified_header = jwt.get_unverified_header(token)
            if unverified_header.get('alg') == 'none':
                # Bypass signature validation
                payload = jwt.decode(token, options={"verify_signature": False})
            else:
                # Validate with weak secret
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
            current_user = User.query.get(payload['user_id'])
            if not current_user:
                return jsonify({"message": "User not found!"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except Exception as e:
            return jsonify({"message": "Token is invalid!", "error": str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    # Planted Vulnerability: No rate limiting is applied to this endpoint.
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400
        
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({"message": "Invalid credentials"}), 401
        
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user.password_hash != password_hash:
        return jsonify({"message": "Invalid credentials"}), 401
        
    # Generate JWT
    payload = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role
    }
    # Expire check is theoretically present but standard PyJWT requires exp claim.
    # If exp claim is missing from payload, PyJWT does not fail on expiry. 
    # So we intentionally omit the 'exp' claim to simulate missing expiration validation!
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    
    return jsonify({
        "token": token,
        "user": user.to_dict()
    }), 200

@auth_bp.route('/api/users/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400
        
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 400
        
    # Planted Vulnerability: Mass Assignment
    # We pass the entire request payload directly to the User constructor.
    # If the payload includes 'role' or 'is_admin', it will be applied to the model.
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # We remove password from data and insert password_hash
    user_data = data.copy()
    user_data.pop('password', None)
    user_data['password_hash'] = password_hash
    
    try:
        new_user = User(**user_data)
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Registration failed", "error": str(e)}), 500
        
    return jsonify({
        "message": "User registered successfully",
        "user": new_user.to_dict()
    }), 201
