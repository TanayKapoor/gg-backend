# application.py
from flask import Flask, jsonify
from flask_cors import CORS
from flasgger import Swagger
from authentication import auth_bp, jwt, oauth

application = Flask(__name__)
swagger = Swagger(application)
CORS(application)

# Register JWT and OAuth configurations
application.config['JWT_SECRET_KEY'] = auth_bp.config['JWT_SECRET_KEY']
application.config['SECRET_KEY'] = auth_bp.config['SECRET_KEY']
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

if __name__ == '__main__':
        application.run(host="0.0.0.0", port=5000)