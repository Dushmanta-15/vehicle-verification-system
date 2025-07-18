# 🚗 Vehicle Verification System

A comprehensive digital vehicle verification platform that combines **facial recognition**, **cryptographic security**, and **blockchain technology** to provide tamper-proof vehicle identity verification.

## 🌟 Features

### 🔐 Multi-Layer Security
- **Facial Recognition Authentication** - Advanced biometric verification using OpenCV and face_recognition
- **Digital Certificates & Signatures** - RSA-2048 cryptographic security
- **Blockchain Integration** - Immutable transaction logging
- **QR Code Verification** - Tamper-proof vehicle identification

### 👤 User Management
- Secure user registration with facial biometrics
- Multi-factor authentication (password + face)
- Personal vehicle portfolio management
- Digital certificate generation

### 🚙 Vehicle Management
- Vehicle registration with encrypted details
- QR code generation for instant verification
- Digital signature validation
- Blockchain-backed audit trails

### 📊 Admin Dashboard
- Real-time system monitoring
- Anomaly detection (statistical + ML-based)
- User and vehicle management
- Security analytics and reporting
- Blockchain integrity verification

### 🤖 AI-Powered Security
- **Isolation Forest** machine learning for anomaly detection
- Real-time threat monitoring
- Automated security alerts
- Pattern recognition for suspicious activities

## 🛠️ Technology Stack

### Backend
- **Python 3.8+**
- **Flask** - Web framework
- **SQLAlchemy** - Database ORM
- **MySQL** - Primary database
- **Flask-Mail** - Email functionality

### Security & Cryptography
- **Cryptography** - RSA encryption and digital signatures
- **face_recognition** - Facial biometric authentication
- **OpenCV** - Image processing
- **Custom Blockchain** - Transaction immutability

### Machine Learning
- **scikit-learn** - Anomaly detection
- **NumPy** - Numerical computations
- **Pandas** - Data analysis

### Frontend
- **HTML5/CSS3/JavaScript**
- **Tailwind CSS** - Styling framework
- **Responsive Design** - Mobile-friendly interface

## 📋 Prerequisites

### System Requirements
- Python 3.8 or higher
- MySQL 8.0+
- CMake (for dlib compilation)
- Visual Studio Build Tools (Windows)

### Python Packages
```bash
pip install -r requirements.txt
```

## ⚡ Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/vehicle-verification-system.git
cd vehicle-verification-system
```

### 2. Environment Setup
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Database Configuration
```bash
# Create MySQL database
mysql -u root -p
CREATE DATABASE vehicle_verification CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Update `config.py` with your database credentials:
```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://username:password@localhost/vehicle_verification'
```

### 4. Initialize Database
```bash
# Create database tables
python migrate.py

# Create admin user
python create_admin.py
```

### 5. Run the Application
```bash
python run.py
```

Visit `http://localhost:5000` to access the application.

## 📁 Project Structure

```
vehicle-verification-system/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── models/                  # Database models
│   │   ├── user.py             # User model
│   │   ├── vehicle.py          # Vehicle model
│   │   ├── admin.py            # Admin model
│   │   ├── verification_attempt.py
│   │   └── request_log.py
│   ├── routes/                  # Application routes
│   │   ├── main_routes.py      # User routes
│   │   └── admin_routes.py     # Admin routes
│   ├── utils.py                # Utility functions
│   ├── templates/              # HTML templates
│   │   ├── admin/              # Admin interface
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── register.html
│   │   └── dashboard.html
│   └── static/                 # Static files
│       ├── css/
│       ├── js/
│       ├── keys/               # Private keys (secure)
│       └── uploads/
├── config.py                   # Configuration settings
├── requirements.txt            # Python dependencies
├── run.py                     # Application entry point
├── create_admin.py            # Admin user creation
└── README.md
```

## 🔧 Configuration

### Database Setup
1. Install MySQL and create a database
2. Update database URL in `config.py`
3. Run migrations to create tables

### Email Configuration (Optional)
For password reset functionality:
```python
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'your_email@gmail.com'
MAIL_PASSWORD = 'your_app_password'
```

### Security Settings
- Change `SECRET_KEY` in production
- Set proper file permissions for keys directory
- Configure SSL/HTTPS for production deployment

## 📖 Usage Guide

### For Users

#### 1. Registration
1. Navigate to `/register`
2. Fill in personal details
3. Upload a clear face photo
4. Submit registration form

#### 2. Vehicle Registration
1. Login to dashboard
2. Click "Add Vehicle"
3. Enter vehicle details
4. Generate QR code for verification

#### 3. Vehicle Verification
1. Use `/verify` endpoint
2. Scan QR code or upload image
3. Get instant verification results

### For Administrators

#### 1. Admin Access
- Login at `/admin/login`
- Default credentials: `admin` / `admin123` (change immediately!)

#### 2. System Monitoring
- View real-time statistics
- Monitor user activity
- Check security alerts

#### 3. Anomaly Detection
- Access security dashboard
- Review ML-powered threat detection
- Investigate suspicious activities

## 🔒 Security Features

### Cryptographic Security
- **RSA-2048** encryption for sensitive data
- **Digital signatures** for data integrity
- **Certificate-based** authentication
- **SHA-256** hashing algorithms

### Blockchain Integration
- **Immutable transaction logs**
- **Proof-of-work** consensus
- **Distributed verification**
- **Audit trail** for all activities

### Anomaly Detection
- **Statistical analysis** for unusual patterns
- **Machine learning** (Isolation Forest) for threat detection
- **Real-time monitoring** of system activities
- **Automated alerting** for security events

## 🚀 API Endpoints

### User Endpoints
```
POST /api/register          # User registration
POST /api/login            # User authentication
POST /api/vehicles/add     # Add new vehicle
POST /api/vehicles/verify  # Verify vehicle
GET  /api/vehicles         # List user vehicles
```

### Admin Endpoints
```
GET  /admin/dashboard      # Admin dashboard
GET  /admin/users          # Manage users
GET  /admin/vehicles       # Manage vehicles
GET  /admin/security       # Security monitoring
GET  /admin/blockchain     # Blockchain status
```

## 🤝 Contributing

This is a proprietary project and **contributions are not accepted** at this time. The code is shared for **demonstration and portfolio purposes only**.

If you're interested in collaboration or licensing opportunities, please contact [your-email@domain.com].

## 📄 License

This project is proprietary software. All rights reserved. See the [LICENSE](LICENSE) file for details.

**⚠️ IMPORTANT:** This software is for demonstration and portfolio purposes only. Commercial use, distribution, or modification without explicit permission is strictly prohibited.

## 🐛 Known Issues & Troubleshooting

### Common Installation Issues

#### dlib/face_recognition Installation
```bash
# Windows users may need:
pip install cmake
pip install dlib
pip install face_recognition

# If issues persist:
conda install -c conda-forge dlib
pip install face_recognition
```

#### MySQL Connection Issues
- Ensure MySQL server is running
- Check firewall settings
- Verify database credentials
- Confirm database exists and has proper charset

### Performance Optimization
- Use production WSGI server (Gunicorn, uWSGI)
- Configure database connection pooling
- Implement Redis for session storage
- Enable SSL/HTTPS for production

## 🚀 Deployment

### Production Considerations
1. **Security**: Use environment variables for sensitive data
2. **Database**: Configure proper backup strategies
3. **SSL**: Implement HTTPS with valid certificates
4. **Monitoring**: Set up logging and error tracking
5. **Scaling**: Consider load balancing for high traffic




## 🎯 Future Enhancements

- [ ] Mobile application (React Native/Flutter)
- [ ] Advanced ML models for fraud detection
- [ ] Integration with government databases
- [ ] Multi-language support
- [ ] API rate limiting and authentication
- [ ] Advanced reporting and analytics
- [ ] IoT device integration

---

**Made with ❤️ for secure vehicle verification**