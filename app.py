from flask import Flask
from flask_cors import CORS
from extensions import mysql, bcrypt
import os

# Create app and configure CORS
app = Flask(__name__)

# ---
## IMPORTANT SECURITY WARNING: Allowing ALL Origins

CORS(app, resources={r"/*": {"origins": "*"}})
# This configuration allows requests from ANY origin to ANY route in your API.
# While convenient for development, using "origins": "*" in a production environment
# is a significant security risk as it makes your API vulnerable to Cross-Site Request Forgery (CSRF)
# and other malicious attacks.

# For production, ALWAYS explicitly list the origins that should be allowed:
# CORS(app, resources={r"/*": {"origins": ["http://yourfrontend.com", "https://anotherfrontend.com"]}})


# MySQL Configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'flask_api')
app.config['MYSQL_CHARSET'] = 'utf8mb4'

# Email Configuration
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASS')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Initialize extensions
mysql.init_app(app)
bcrypt.init_app(app)

# Import and register blueprints
from routes.auth import auth_bp
from routes.user import user_bp

app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)