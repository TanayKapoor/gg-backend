from flask import Flask, jsonify
from flask_cors import CORS
from flasgger import Swagger
from authentication import auth_bp
from extensions import db, jwt, oauth

# Initialize Flask app
application = Flask(__name__)
swagger = Swagger(application)
CORS(application)

# Configure application
application.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:root%40123@localhost:3306/gg-db"
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application.config['JWT_SECRET_KEY'] = auth_bp.config['JWT_SECRET_KEY']
application.config['SECRET_KEY'] = auth_bp.config['SECRET_KEY']
application.config['SECRET_KEY'] = auth_bp.config['SECRET_KEY']

# Initialize database and extensions
db.init_app(application)
jwt.init_app(application)
oauth.init_app(application)

# Register the authentication blueprint
application.register_blueprint(auth_bp, url_prefix='/auth')

@application.route('/api/hello', methods=['GET'])
def hello():
    """
    An example endpoint.
    ---
    responses:
      200:
        description: A successful response
    """
    response = "Hello, World!"
    return jsonify(response)

# Create tables before the first request
tables_created = False

@application.before_request
def create_tables(): ...

if __name__ == '__main__':
    application.run(host="0.0.0.0", port=5000)