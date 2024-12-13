import logging
import os
import binascii
from flask import Blueprint, request, jsonify, redirect, url_for, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from authlib.integrations.flask_client import OAuth

# Configure logging
logging.basicConfig(level=logging.DEBUG)

auth_bp = Blueprint('auth', __name__)

# JWT and configuration
auth_bp.config = {
    'JWT_SECRET_KEY': 'your_jwt_secret_key',
    'SECRET_KEY': 'your_oauth_secret_key'
}
jwt = JWTManager()
oauth = OAuth()

# OAuth configuration for Google
oauth.register(
    name='google',
    client_id='682315773396-j00bqmrr9pvjbm2evl33e59ji7bmge4t.apps.googleusercontent.com',
    client_secret='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',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/auth/callback',
    client_kwargs={'scope': 'openid profile email phone'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# Dummy user data
users = {
    "testuser": {"password": "testpassword", "email": "testuser@example.com"},
    "Admin": {"password": "adminpassword", "email": "admin@admin.com"}
}

@auth_bp.route('/login', methods=['POST'])
def login():
    identifier = request.json.get('identifier', None)
    password = request.json.get('password', None)
    
    user = None
    for username, user_data in users.items():
        if (username == identifier or user_data['email'] == identifier) and user_data['password'] == password:
            user = username
            break
    
    if not user:
        return jsonify({"msg": "Bad username/email or password"}), 401

    access_token = create_access_token(identity=user)
    return jsonify(access_token=access_token)

@auth_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

def generate_nonce(length=32):
    return binascii.hexlify(os.urandom(length)).decode()

@auth_bp.route('/oauth/login')
def auth_login():
    redirect_uri = url_for('auth.auth_callback', _external=True)
    nonce = generate_nonce()
    session['nonce'] = nonce
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@auth_bp.route('/auth/callback')
def auth_callback():
    try:
        token = oauth.google.authorize_access_token()
        nonce = session.pop('nonce', None)
        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        
        access_token = create_access_token(identity=user_info['email'])
        
        return jsonify(user_info=user_info, access_token=access_token)
    except Exception as e:
        logging.error("Error during OAuth callback", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    session.clear()
    return response