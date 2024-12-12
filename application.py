# sample flask API
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import requests
import os
from flasgger import Swagger

application = Flask(__name__)
swagger = Swagger(application)
CORS(application)

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