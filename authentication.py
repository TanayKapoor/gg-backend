import logging
import os
import binascii
from flask import Blueprint, request, jsonify, redirect, url_for, session
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db, jwt, oauth  # Import db, jwt, and oauth from extensions
from datetime import datetime, timedelta
from sqlalchemy import ForeignKey

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

auth_bp = Blueprint('auth', __name__)

# JWT and configuration
auth_bp.config = {
    'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY'),
    'SECRET_KEY': os.getenv('OAUTH_SECRET_KEY'),
}

# OAuth configuration for Google
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
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


# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    avatar = db.Column(db.String(255))
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    birth_date = db.Column(db.Date)
    phone_number = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)

    def __repr__(self):
        return f"<User {self.username}>"
    

# Define SocialAccount model
class SocialAccount(db.Model):
    __tablename__ = 'social_accounts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    provider = db.Column(db.String(255), nullable=False)
    provider_user_id = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), nullable=False)
    avatar = db.Column(db.String(255))
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)

# Define LoginSession model
class LoginSession(db.Model):
    __tablename__ = 'login_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(255))
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime, nullable=False)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    first_name = data.get('first_name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    created_at = datetime.now()

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password_hash=hashed_password, created_at=created_at, first_name=first_name)
    db.session.add(new_user)
    db.session.commit()
    access_token = generate_user_access_token(new_user)
    return jsonify(access_token=access_token, msg="User registered successfully"), 201

@auth_bp.route('/update_user', methods=['PUT'])
@jwt_required()
def update_user():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    data = request.json
    new_username = data.get('username', user.username)

    # Check if the new username is already taken by another user
    if new_username != user.username and User.query.filter_by(username=new_username).first():
        return jsonify({"msg": "Username is already taken"}), 400

    user.username = new_username
    user.avatar = data.get('avatar', user.avatar)
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.birth_date = data.get('birth_date', user.birth_date)
    user.phone_number = data.get('phone_number', user.phone_number)
    user.updated_at = datetime.now()

    db.session.commit()

    return jsonify({"msg": "User updated successfully"}), 200

@auth_bp.route('/login', methods=['POST'])
def login():
    identifier = request.json.get('identifier')
    password = request.json.get('password')

    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"msg": "Invalid username/email or password"}), 401
    
    access_token = generate_user_access_token(user)

    return jsonify(access_token=access_token)

def generate_nonce(length=32):
    return binascii.hexlify(os.urandom(length)).decode()

@auth_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    return jsonify({"logged_in_as": user.username}), 200


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
        # if account exists in users table, return access token
        user = User.query.filter_by(email=user_info['email']).first()
        if user:
            print("User exists")
            access_token = generate_user_access_token(user)
            return jsonify(access_token=access_token) 
        else:
            # Check if social account exists
            social_account = SocialAccount.query.filter_by(provider='google', provider_user_id=user_info['sub']).first()
            if not social_account:
                # Create new social account
                user = User.query.filter_by(email=user_info['email']).first()
                if not user:
                    user = User(
                        avatar=user_info.get('picture'),
                        email=user_info['email'],
                        first_name=user_info.get('given_name'),
                        last_name=user_info.get('family_name'), 
                        username=user_info['email'].split('@')[0], 
                        created_at=datetime.now()
                        )
                    db.session.add(user)
                    db.session.commit()
                
                social_account = SocialAccount(
                    user_id=user.id,
                    provider='google',
                    provider_user_id=user_info['sub'],
                    email=user_info['email'],
                    avatar=user_info.get('picture'),
                    created_at=datetime.now()
                )
                db.session.add(social_account)
                db.session.commit()            
            return jsonify(user_info=user_info, msg="Social account created successfully")
    except Exception as e:
        logging.error("Error during OAuth callback", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    login_session = LoginSession.query.filter_by(user_id=user.id).first()
    if login_session:
        login_session.expires_at = datetime.now()
        db.session.commit()
    return jsonify({"msg": "User logged out successfully"}), 200

# Method to generate user access token and add it to login session
def generate_user_access_token(user):
    # Check if token is present in login session with user_id
    login_session = LoginSession.query.filter_by(user_id=user.id).first()
    
    if login_session:
        # Check if the token is expired
        if login_session.expires_at > datetime.now():
            return login_session.token
    
    # Create a new session
    access_token = create_access_token(identity=user.email)
    new_login_session = LoginSession(
        user_id=user.id,
        token=access_token,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        created_at=datetime.now(),
        updated_at=datetime.now(),
        expires_at=datetime.now() + timedelta(hours=1)  # Example expiration time
    )
    db.session.add(new_login_session)
    db.session.commit()
    return access_token