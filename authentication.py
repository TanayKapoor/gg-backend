# auth.py
from flask import Blueprint, request, jsonify, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from authlib.integrations.flask_client import OAuth

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
        client_id='your_google_client_id',
        client_secret='your_google_client_secret',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        access_token_url='https://accounts.google.com/o/oauth2/token',
        access_token_params=None,
        refresh_token_url=None,
        redirect_uri='http://localhost:5000/auth/callback',
        client_kwargs={'scope': 'openid profile email'}
)

# Dummy user data
users = {
        "testuser": {"password": "testpassword", "email": "testuser@example.com"}
}

@auth_bp.route('/login', methods=['POST'])
def login():
        """
        User login endpoint.
        ---
        tags:
            - Authentication
        parameters:
            - name: identifier
                in: body
                type: string
                required: true
                description: The username or email of the user.
            - name: password
                in: body
                type: string
                required: true
                description: The password of the user.
        responses:
            200:
                description: Login successful
            401:
                description: Bad username/email or password
        """
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
        """
        Protected endpoint.
        ---
        tags:
            - Authentication
        responses:
            200:
                description: Access granted
            401:
                description: Missing or invalid token
        """
        current_user = get_jwt_identity()
        return jsonify(logged_in_as=current_user), 200

@auth_bp.route('/auth/login')
def auth_login():
        """
        OAuth login endpoint.
        ---
        tags:
            - Authentication
        responses:
            302:
                description: Redirect to Google OAuth
        """
        redirect_uri = url_for('auth.auth_callback', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

@auth_bp.route('/auth/callback')
def auth_callback():
        """
        OAuth callback endpoint.
        ---
        tags:
            - Authentication
        responses:
            200:
                description: OAuth login successful
        """
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token)
        return jsonify(user_info)