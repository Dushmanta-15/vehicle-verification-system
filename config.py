#user_config
import os
from urllib.parse import quote_plus

# Define BASE_DIR
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Database configuration
    PASSWORD = quote_plus('15August1947@')  # URL encode the password
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://root:{PASSWORD}@127.0.0.1:3306/vehicle_verification?charset=utf8mb4'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # MySQL specific settings
    MYSQL_DATABASE_CHARSET = 'utf8mb4'
    MYSQL_CHARSET = 'utf8mb4'
    MYSQL_COLLATION = 'utf8mb4_unicode_ci'

    # Admin configuration
    ADMIN_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'app', 'static', 'admin', 'uploads')
    ADMIN_SESSION_TIMEOUT = 3600  # 1 hour
    
    # Security
    SECRET_KEY = 'your-secret-key'  # Change this in production
    
    # File storage paths
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'app', 'static', 'uploads')
    FACES_FOLDER = os.path.join(BASE_DIR, 'app', 'static', 'faces')
    CERTIFICATES_PATH = os.path.join(BASE_DIR, 'app', 'static', 'certificates')
    KEYS_PATH = os.path.join(BASE_DIR, 'app', 'static', 'keys')
    
    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    
    # Session configuration
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    
    # Database field sizes
    DB_FIELD_SIZES = {
        'username_length': 80,
        'email_length': 120,
        'password_hash_length': 255,  # Increased for scrypt hash
        'vehicle_number_length': 20
    }
    
    # Face recognition settings
    FACE_RECOGNITION_CONFIDENCE_THRESHOLD = 80
    FACE_IMAGE_SIZE = (200, 200)
    
    # RSA Key settings
    RSA_KEY_SIZE = 2048
    CERTIFICATE_VALIDITY_DAYS = 365
    
    # Create required directories
    for path in [UPLOAD_FOLDER, FACES_FOLDER, CERTIFICATES_PATH, KEYS_PATH]:
        os.makedirs(path, exist_ok=True)
        
    # Set secure permissions for sensitive directories
    try:
        os.chmod(KEYS_PATH, 0o700)  # Restrict access to keys directory
        os.chmod(CERTIFICATES_PATH, 0o755)  # Allow read access to certificates
    except Exception as e:
        print(f"Warning: Could not set directory permissions: {e}")

    # Logging configuration
    LOGGING_CONFIG = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
            }
        },
        'handlers': {
            'file': {
                'class': 'logging.FileHandler',
                'filename': os.path.join(BASE_DIR, 'app.log'),
                'formatter': 'default'
            }
        },
        'root': {
            'level': 'INFO',
            'handlers': ['file']
        }
    }

    @staticmethod
    def init_app(app):
        """Initialize application configuration"""
        # Ensure the MySQL connection uses proper charset
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            "pool_pre_ping": True,
            "pool_recycle": 300,
            "connect_args": {
                "charset": "utf8mb4"
            }
        }
        
        # Create logging directory if it doesn't exist
        log_dir = os.path.dirname(os.path.join(Config.BASE_DIR, 'app.log'))
        os.makedirs(log_dir, exist_ok=True)