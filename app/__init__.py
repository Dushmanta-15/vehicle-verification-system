# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import os

# Initialize extensions first, before any imports that might need them
db = SQLAlchemy()
mail = Mail()

def create_app():
    app = Flask(__name__)
    
    # Import config here to avoid circular imports
    from config import Config
    app.config.from_object(Config)
    Config.init_app(app)
    
    # Initialize extensions with app
    db.init_app(app)
    
    # Email configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'kdushmanta41@gmail.com'
    app.config['MAIL_PASSWORD'] = 'jcro sdww ntbl ljel'  # Secure in production
    app.config['MAIL_DEFAULT_SENDER'] = 'kdushmanta41@gmail.com'
    mail.init_app(app)
    
    # Create database tables before registering blueprints
    with app.app_context():
        # Import models - must be done here to avoid circular imports
        from app.models.user import User
        from app.models.vehicle import Vehicle
        from app.models.admin import Admin
        from app.models.verification_attempt import VerificationAttempt
        from app.models.request_log import RequestLog
        
        # Create tables
        db.create_all()
        
        # Create directories
        create_required_directories(app)
    
    # Register blueprints - do this after db initialization
    from app.routes import main as main_blueprint
    from app.routes.admin import admin_bp as admin_blueprint

    app.register_blueprint(admin_blueprint, url_prefix='/admin')
    app.register_blueprint(main_blueprint)
    
    # Set up request middleware for logging and anomaly detection
    from app.middleware import setup_request_middleware
    setup_request_middleware(app)
    
    return app

def create_required_directories(app):
    """Create required directories for the application"""
    # Get Config from app config
    directories = [
        app.config['UPLOAD_FOLDER'],
        app.config['FACES_FOLDER'],
        app.config['CERTIFICATES_PATH'],
        app.config['KEYS_PATH'],
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Set secure permissions for sensitive directories
    try:
        os.chmod(app.config['KEYS_PATH'], 0o700)  # Restrict access to keys directory
    except Exception as e:
        print(f"Warning: Could not set secure permissions: {e}")