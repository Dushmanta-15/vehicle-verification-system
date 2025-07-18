#user_routes
from flask import Blueprint, request, jsonify, current_app, render_template, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from app.models.user import User
from app.models.vehicle import Vehicle
from app.utils import CryptoUtils, FaceAuth
from app import db
import os
from sqlalchemy import func
import base64
import json
from datetime import datetime
from functools import wraps
from flask_mail import Message
from datetime import datetime, timedelta
import jwt
import re 
from flask_mail import Message
from flask import current_app
from app import mail
from app.utils import VehicleBlockchainManager
from datetime import datetime
import json

blockchain_manager = VehicleBlockchainManager()

main = Blueprint('main', __name__)
crypto_utils = CryptoUtils()
face_auth = FaceAuth()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Page Routes
@main.route('/')
def home():
    return render_template('base.html')

@main.route('/register')
def register_page():
    return render_template('register.html')

@main.route('/login')
def login_page():
    return render_template('login.html')

@main.route('/certificates')
@login_required
def certificates_page():
    return render_template('certificates.html')


@main.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get current user
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect('/login')

        # Get user's vehicles
        vehicles = Vehicle.query.filter_by(user_id=user.id).all()
        vehicle_count = len(vehicles)

        # Check certificate validity
        try:
            cert_valid, cert_message = crypto_utils.verify_certificate(user.certificate.encode())
        except:
            cert_valid = False
            cert_message = "Certificate validation failed"

        # Get recent activity (last 5 activities)
        recent_activities = [
            {
                'type': 'vehicle_add',
                'description': f'Added new vehicle {vehicle.vehicle_number}',
                'timestamp': vehicle.created_at.isoformat(),
            }
            for vehicle in vehicles[-5:]  # Get last 5 vehicles
        ]

        # Pass all data to template
        return render_template('dashboard.html',
            user=user,
            vehicle_count=vehicle_count,
            cert_valid=cert_valid,
            cert_message=cert_message,
            recent_activities=recent_activities
        )

    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        session.clear()
        return redirect('/login')

@main.route('/dashboard/vehicles')
@login_required
def vehicles_page():
    return render_template('vehicles.html')

@main.route('/dashboard/verify')
@login_required
def verify_page():
    return render_template('verify.html')

@main.route('/api/register', methods=['POST'])
def register_api():
    try:
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        face_image = request.files.get('face_image')
        
        # Get new fields
        first_name = request.form.get('firstName')
        middle_name = request.form.get('middleName')  # Optional
        last_name = request.form.get('lastName')
        country_code = request.form.get('countryCode')
        mobile = request.form.get('mobile')
        address = request.form.get('address')
        gender = request.form.get('gender')

        # Validate required fields
        required_fields = {
            'username': username,
            'email': email,
            'password': password,
            'first_name': first_name,
            'last_name': last_name,
            'mobile': mobile,
            'address': address,
            'gender': gender
        }

        for field_name, field_value in required_fields.items():
            if not field_value:
                return jsonify({'error': f'{field_name.replace("_", " ").title()} is required'}), 400

        # Validate name fields (only letters and spaces)
        name_pattern = r'^[A-Za-z ]+$'
        if not re.match(name_pattern, first_name):
            return jsonify({'error': 'First name should only contain letters and spaces'}), 400
        if not re.match(name_pattern, last_name):
            return jsonify({'error': 'Last name should only contain letters and spaces'}), 400
        if middle_name and not re.match(name_pattern, middle_name):
            return jsonify({'error': 'Middle name should only contain letters and spaces'}), 400

        # Validate mobile number (exactly 10 digits)
        if not re.match(r'^[0-9]{10}$', mobile):
            return jsonify({'error': 'Mobile number must be exactly 10 digits'}), 400

        # Validate password (at least 8 characters, alphanumeric)
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            return jsonify({'error': 'Password must be at least 8 characters and contain both letters and numbers'}), 400

        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 400
        if User.query.filter_by(mobile_number=f"{country_code}{mobile}").first():
            return jsonify({'error': 'Mobile number already registered'}), 400

        # Validate face image
        if not face_image:
            return jsonify({'error': 'Face image is required'}), 400

        # Process face image
        face_image_bytes = face_image.read()
        
        # Check face image quality
        quality_check = face_auth.check_face_quality(face_image_bytes)
        if not quality_check['valid']:
            return jsonify({'error': quality_check['message']}), 400

        # Process face for encoding
        face_encoding = face_auth.process_face_image(face_image_bytes)
        if not face_encoding:
            return jsonify({'error': 'Failed to process face image. Please ensure good lighting and face is clearly visible'}), 400

        # Generate key pair and certificate
        private_key, public_key = crypto_utils.generate_key_pair()
        
        # Create certificate
        user_data = {
            'username': username,
            'email': email,
            'public_key': public_key
        }
        certificate = crypto_utils.generate_certificate(user_data, private_key)

        # Create user with all fields
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            mobile_number=f"{country_code}{mobile}",
            address=address,
            gender=gender,
            public_key=public_key.decode(),
            certificate=certificate.decode(),
            face_encoding=base64.b64encode(face_encoding).decode()
        )
        
        db.session.add(user)
        db.session.commit()

        # Save private key securely
        key_path = os.path.join(current_app.config['KEYS_PATH'], f'{user.id}_private.pem')
        with open(key_path, 'wb') as f:
            f.write(private_key)

        return jsonify({
            'message': 'Registration successful',
            'user_id': user.id
        })

    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {str(e)}")
        print("Request form data:", request.form)  # Print form data
        print("Request files:", request.files)     # Print files
        return jsonify({'error': 'Registration failed'}), 500

@main.route('/api/login', methods=['POST'])
def login_api():
    from app.models.verification_attempt import VerificationAttempt
    
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        face_image = request.files.get('face_image')

        # Create verification attempt record
        verification_attempt = VerificationAttempt(
            verification_type='face',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None
        )

        if not all([username, password, face_image]):
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = "Missing required fields"
            db.session.add(verification_attempt)
            db.session.commit()
            return jsonify({'error': 'Missing required fields'}), 400

        # Find user
        user = User.query.filter_by(username=username).first()
        if not user:
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = "Invalid username"
            db.session.add(verification_attempt)
            db.session.commit()
            return jsonify({'error': 'Invalid username or password'}), 401
            
        # Update verification record with user ID
        verification_attempt.user_id = user.id

        # Verify password
        if not check_password_hash(user.password_hash, password):
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = "Invalid password"
            db.session.add(verification_attempt)
            db.session.commit()
            return jsonify({'error': 'Invalid username or password'}), 401

        # Process face image
        face_image_bytes = face_image.read()

        # Check face image quality first
        quality_check = face_auth.check_face_quality(face_image_bytes)
        if not quality_check['valid']:
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = quality_check['message']
            db.session.add(verification_attempt)
            db.session.commit()
            return jsonify({'error': quality_check['message']}), 400

        # Verify face
        try:
            stored_encoding = base64.b64decode(user.face_encoding)
            if not face_auth.verify_face(face_image_bytes, stored_encoding):
                verification_attempt.is_successful = False
                verification_attempt.failure_reason = "Face verification failed"
                db.session.add(verification_attempt)
                db.session.commit()
                return jsonify({'error': 'Face verification failed. Please ensure good lighting and face is clearly visible'}), 401
        except Exception as e:
            print(f"Face verification error: {str(e)}")
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = f"Face verification error: {str(e)}"
            db.session.add(verification_attempt)
            db.session.commit()
            return jsonify({'error': 'Face verification failed. Please try again'}), 401

        # Create session
        session['user_id'] = user.id
        session.permanent = True  # Make session persistent
        
        # Update user's last login time
        user.last_login = datetime.utcnow()
        
        # Record successful verification
        verification_attempt.is_successful = True
        db.session.add(verification_attempt)
        db.session.commit()

        # Check for suspicious activity
        from app.utils import AnomalyDetection
        
        # Check if this user has too many recent verification attempts
        verification_stats = db.session.query(
            func.count(VerificationAttempt.id)
        ).filter(
            VerificationAttempt.user_id == user.id,
            VerificationAttempt.created_at >= (datetime.utcnow() - timedelta(hours=24))
        ).scalar()
        
        if verification_stats and verification_stats > 10:
            # Log this as a potential security issue but don't block the login
            print(f"Security alert: User {user.username} has {verification_stats} verification attempts in the last 24 hours")
            
            # You could send an alert email here or take other actions
            # such as requiring additional verification

        return jsonify({
            'message': 'Login successful',
            'user_id': user.id
        })

    except Exception as e:
        # Log the error
        print(f"Login error: {str(e)}")
        try:
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = f"General error: {str(e)}"
            db.session.add(verification_attempt)
            db.session.commit()
        except:
            # If we can't log the verification attempt, just pass
            pass
            
        return jsonify({'error': 'Login failed. Please try again'}), 500
@main.route('/api/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logout successful'})

# Vehicle Management APIs
@main.route('/api/vehicles', methods=['GET'])
@login_required
def get_user_vehicles():
    user = User.query.get(session['user_id'])
    vehicles = [
        {
            'id': vehicle.id,
            'vehicle_number': vehicle.vehicle_number,
            'owner_name': vehicle.owner_name,
            'model': vehicle.model,
            'year': vehicle.year,
            'qr_code': vehicle.qr_code
        } 
        for vehicle in user.vehicles
    ]
    return jsonify(vehicles)

@main.route('/api/vehicles/add', methods=['POST'])
@login_required
def add_vehicle():
    try:
        user = User.query.get(session['user_id'])
        
        vehicle_data = {
            'vehicle_number': request.form.get('vehicle_number'),
            'owner_name': request.form.get('owner_name'),
            'model': request.form.get('model'),
            'year': request.form.get('year'),
            'additional_details': request.form.get('additional_details')
        }

        if not all([vehicle_data['vehicle_number'], vehicle_data['owner_name']]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Get user's private key
        key_path = os.path.join(current_app.config['KEYS_PATH'], f'{user.id}_private.pem')
        with open(key_path, 'rb') as f:
            private_key = f.read()

        # First encrypt the data
        encrypted_data = crypto_utils.encrypt_vehicle_data(
            vehicle_data, 
            user.public_key.encode()
        )
        
        # Sign the encrypted data
        digital_signature = crypto_utils.sign_data(
            encrypted_data,
            private_key
        )

        # Create QR code data
        qr_data = {
            'encrypted_data': encrypted_data,
            'digital_signature': digital_signature,
            'user_id': user.id,
            'timestamp': datetime.utcnow().isoformat()
        }

        print("QR Data created:")
        print(f"Encrypted data (first 50 chars): {encrypted_data[:50]}")
        print(f"Signature (first 50 chars): {digital_signature[:50]}")

        # Generate QR code and save vehicle
        qr_code = crypto_utils.generate_qr_code(qr_data)
        vehicle = Vehicle(
            vehicle_number=vehicle_data['vehicle_number'],
            owner_name=vehicle_data['owner_name'],
            model=vehicle_data.get('model'),
            year=vehicle_data.get('year'),
            encrypted_details=encrypted_data,
            digital_signature=digital_signature,
            qr_code=qr_code,
            user_id=user.id
        )

        db.session.add(vehicle)
        db.session.flush()  # Get vehicle ID
        
        # 🔗 NEW: Log vehicle registration to blockchain
        try:
            tx_id, block_hash = blockchain_manager.log_vehicle_registration(vehicle)
            vehicle.blockchain_record = tx_id
            vehicle.last_blockchain_update = datetime.utcnow()
            print(f"✅ Vehicle registration logged to blockchain: {tx_id}")
        except Exception as e:
            print(f"⚠️ Blockchain logging failed: {e}")
            # Don't fail the registration if blockchain logging fails
        
        db.session.commit()

        return jsonify({
            'message': 'Vehicle added successfully',
            'qr_code': qr_code,
            'blockchain_logged': bool(vehicle.blockchain_record),
            'blockchain_tx': vehicle.blockchain_record
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error adding vehicle: {str(e)}")
        return jsonify({'error': f'Failed to add vehicle: {str(e)}'}), 500

@main.route('/api/vehicles/verify', methods=['POST'])
@login_required
def verify_vehicle():
    """
    Enhanced verification function that logs verification attempts to blockchain
    """
    from app.models.verification_attempt import VerificationAttempt
    
    try:
        print("Starting verification process...")
        qr_data = request.json.get('qr_data')
        
        # Create a verification attempt log entry
        verification_attempt = VerificationAttempt(
            user_id=session.get('user_id'),
            verification_type='qr_code',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None
        )
        
        # Parse QR data if it's a string
        if isinstance(qr_data, str):
            try:
                qr_data = json.loads(qr_data)
            except json.JSONDecodeError:
                verification_attempt.is_successful = False
                verification_attempt.failure_reason = "Invalid QR code format"
                db.session.add(verification_attempt)
                db.session.flush()  # Get ID for blockchain
                
                # Log failed verification to blockchain
                try:
                    tx_id, block_hash = blockchain_manager.log_verification_attempt(verification_attempt)
                    verification_attempt.blockchain_hash = tx_id
                    verification_attempt.blockchain_verified = True
                except Exception as e:
                    print(f"Blockchain logging failed: {e}")
                
                db.session.commit()
                return jsonify({'error': 'Invalid QR code format'}), 400
        
        print("QR Data:", qr_data)
        
        # Get vehicle owner
        user = User.query.get(qr_data['user_id'])
        if not user:
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = "Invalid vehicle owner"
            db.session.add(verification_attempt)
            db.session.flush()
            
            # Log failed verification to blockchain
            try:
                tx_id, block_hash = blockchain_manager.log_verification_attempt(verification_attempt)
                verification_attempt.blockchain_hash = tx_id
                verification_attempt.blockchain_verified = True
            except Exception as e:
                print(f"Blockchain logging failed: {e}")
            
            db.session.commit()
            return jsonify({'error': 'Invalid vehicle owner'}), 404
            
        print(f"Found user: {user.username}")
        
        # Try to find the vehicle based on encrypted data
        vehicle = Vehicle.query.filter_by(encrypted_details=qr_data['encrypted_data']).first()
        if vehicle:
            verification_attempt.vehicle_id = vehicle.id

        # Verify digital signature
        try:
            print("Verifying signature...")
            
            signature_valid = crypto_utils.verify_signature(
                qr_data['encrypted_data'],
                qr_data['digital_signature'],
                user.public_key.encode()
            )
            
            if not signature_valid:
                print("Signature verification failed")
                verification_attempt.is_successful = False
                verification_attempt.failure_reason = "Invalid digital signature"
                db.session.add(verification_attempt)
                db.session.flush()
                
                # Log failed verification to blockchain
                try:
                    tx_id, block_hash = blockchain_manager.log_verification_attempt(verification_attempt)
                    verification_attempt.blockchain_hash = tx_id
                    verification_attempt.blockchain_verified = True
                except Exception as e:
                    print(f"Blockchain logging failed: {e}")
                
                db.session.commit()
                return jsonify({'error': 'Invalid digital signature'}), 401
                
            print("Signature verified successfully")

        except Exception as e:
            print(f"Error during signature verification: {str(e)}")
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = f"Signature verification error: {str(e)}"
            db.session.add(verification_attempt)
            db.session.flush()
            
            # Log failed verification to blockchain
            try:
                tx_id, block_hash = blockchain_manager.log_verification_attempt(verification_attempt)
                verification_attempt.blockchain_hash = tx_id
                verification_attempt.blockchain_verified = True
            except Exception as e:
                print(f"Blockchain logging failed: {e}")
            
            db.session.commit()
            return jsonify({'error': f'Signature verification error: {str(e)}'}), 401

        # Get private key
        key_path = os.path.join(current_app.config['KEYS_PATH'], f'{user.id}_private.pem')
        if not os.path.exists(key_path):
            print(f"Private key not found at: {key_path}")
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = "Private key not found"
            db.session.add(verification_attempt)
            db.session.flush()
            
            # Log failed verification to blockchain
            try:
                tx_id, block_hash = blockchain_manager.log_verification_attempt(verification_attempt)
                verification_attempt.blockchain_hash = tx_id
                verification_attempt.blockchain_verified = True
            except Exception as e:
                print(f"Blockchain logging failed: {e}")
            
            db.session.commit()
            return jsonify({'error': 'Private key not found'}), 500
            
        with open(key_path, 'rb') as f:
            private_key = f.read()

        # Decrypt vehicle data
        try:
            print("Decrypting data...")
            vehicle_data = crypto_utils.decrypt_vehicle_data(
                qr_data['encrypted_data'],
                private_key
            )
            print("Decrypted vehicle data:", vehicle_data)
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = f"Decryption error: {str(e)}"
            db.session.add(verification_attempt)
            db.session.flush()
            
            # Log failed verification to blockchain
            try:
                tx_id, block_hash = blockchain_manager.log_verification_attempt(verification_attempt)
                verification_attempt.blockchain_hash = tx_id
                verification_attempt.blockchain_verified = True
            except Exception as e:
                print(f"Blockchain logging failed: {e}")
            
            db.session.commit()
            return jsonify({'error': 'Failed to decrypt vehicle data'}), 500

        # Record successful verification
        verification_attempt.is_successful = True
        db.session.add(verification_attempt)
        db.session.flush()  # Get ID for blockchain
        
        # 🔗 NEW: Log successful verification to blockchain
        try:
            tx_id, block_hash = blockchain_manager.log_verification_attempt(verification_attempt)
            verification_attempt.blockchain_hash = tx_id
            verification_attempt.blockchain_verified = True
            print(f"✅ Verification logged to blockchain: {tx_id}")
        except Exception as e:
            print(f"⚠️ Blockchain logging failed: {e}")
            # Don't fail the verification if blockchain logging fails
        
        db.session.commit()

        return jsonify({
            'message': 'Vehicle verified successfully',
            'vehicle_data': vehicle_data,
            'timestamp': qr_data['timestamp'],
            'blockchain_logged': verification_attempt.blockchain_verified,
            'blockchain_tx': verification_attempt.blockchain_hash
        })

    except Exception as e:
        print(f"Verification error: {str(e)}")
        # Log the error in the verification attempt
        try:
            verification_attempt.is_successful = False
            verification_attempt.failure_reason = f"General error: {str(e)}"
            db.session.add(verification_attempt)
            db.session.flush()
            
            # Log failed verification to blockchain
            try:
                tx_id, block_hash = blockchain_manager.log_verification_attempt(verification_attempt)
                verification_attempt.blockchain_hash = tx_id
                verification_attempt.blockchain_verified = True
            except Exception as blockchain_error:
                print(f"Blockchain logging failed: {blockchain_error}")
            
            db.session.commit()
        except:
            pass
            
        return jsonify({'error': f'Failed to verify vehicle: {str(e)}'}), 500
  

@main.route('/api/vehicles/<int:vehicle_id>', methods=['GET'])
@login_required
def get_vehicle(vehicle_id):
    try:
        vehicle = Vehicle.query.get_or_404(vehicle_id)
        
        if vehicle.user_id != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403

        return jsonify({
            'id': vehicle.id,
            'vehicle_number': vehicle.vehicle_number,
            'owner_name': vehicle.owner_name,
            'model': vehicle.model,
            'year': vehicle.year,
            'qr_code': vehicle.qr_code
        })

    except Exception as e:
        print(f"Error getting vehicle: {str(e)}")
        return jsonify({'error': 'Failed to get vehicle details'}), 500

@main.route('/api/vehicles/<int:vehicle_id>/qr-code', methods=['GET'])
@login_required
def get_vehicle_qr(vehicle_id):
    try:
        vehicle = Vehicle.query.get_or_404(vehicle_id)
        
        if vehicle.user_id != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403

        return jsonify({
            'qr_code': vehicle.qr_code
        })

    except Exception as e:
        print(f"Error getting QR code: {str(e)}")
        return jsonify({'error': 'Failed to get QR code'}), 500

@main.route('/api/certificates/current', methods=['GET'])
@login_required
def get_current_certificate():
    try:
        user = User.query.get(session['user_id'])
        cert_info = crypto_utils.get_certificate_info(user.certificate.encode())
        
        return jsonify({
            'certificate': user.certificate,
            'info': cert_info,
            'public_key': user.public_key
        })
    except Exception as e:
        print(f"Error getting certificate: {str(e)}")
        return jsonify({'error': 'Failed to get certificate'}), 500

@main.route('/api/certificates/verify', methods=['POST'])
@login_required
def verify_certificate():
    try:
        certificate_pem = request.json.get('certificate')
        if not certificate_pem:
            return jsonify({
                'valid': False,
                'message': 'No certificate provided'
            }), 400

        # Verify certificate
        is_valid, message = crypto_utils.verify_certificate(certificate_pem.encode())
        
        if not is_valid:
            return jsonify({
                'valid': False,
                'message': message
            })

        # Get certificate info
        cert_info = crypto_utils.get_certificate_info(certificate_pem.encode())
        
        return jsonify({
            'valid': True,
            'message': 'Certificate is valid',
            'info': cert_info
        })

    except Exception as e:
        print(f"Error verifying certificate: {str(e)}")
        return jsonify({
            'valid': False,
            'message': f'Failed to verify certificate: {str(e)}'
        }), 500

# new existing routes

@main.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        email = request.json.get('email')
        print(f"Received email: {email}")  # Debug log
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        user = User.query.filter_by(email=email).first()
        print(f"User found: {user is not None}")  # Debug log
        
        if not user:
            # For security, don't reveal if email exists or not
            return jsonify({'message': 'If the email exists, you will receive a reset link'}), 200

        # Generate token
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, current_app.config['SECRET_KEY'], algorithm='HS256')

        # Create reset link
        reset_link = f"{request.host_url}reset-password/{token}"
        print(f"Reset link generated: {reset_link}")  # Debug log

        try:
            # Create email message
            msg = Message('Password Reset Request',
                         sender=current_app.config['MAIL_USERNAME'],
                         recipients=[user.email])
            
            msg.body = f'''To reset your password, visit the following link:
{reset_link}

If you did not make this request, please ignore this email.

This link is valid for 1 hour.
'''
            # Send email
            mail.send(msg)
            print("Email sent successfully")  # Debug log
            
        except Exception as mail_error:
            print(f"Email sending error: {str(mail_error)}")  # Specific email error
            return jsonify({'error': 'Failed to send email. Please try again.'}), 500

        return jsonify({'message': 'Password reset link sent to email'}), 200

    except Exception as e:
        print(f"Password reset error: {str(e)}")  # Main error log
        return jsonify({'error': str(e)}), 500  # Return actual error message for debugging

@main.route('/reset-password/<token>', methods=['GET'])
def reset_password_page(token):
    try:
        # Verify token
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']
        user = User.query.get(user_id)
        
        if not user:
            return render_template('error.html', message='Invalid or expired reset link'), 400

        # Pass token to template to be used in form submission
        return render_template('reset_password.html', token=token)

    except jwt.ExpiredSignatureError:
        return render_template('error.html', message='Reset link has expired'), 400
    except jwt.InvalidTokenError:
        return render_template('error.html', message='Invalid reset link'), 400

@main.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        token = request.json.get('token')
        new_password = request.json.get('password')

        if not all([token, new_password]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Verify token
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])

        if not user:
            return jsonify({'error': 'Invalid user'}), 400

        # Update password
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        return jsonify({'message': 'Password updated successfully'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Reset link has expired'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid reset link'}), 400
    except Exception as e:
        db.session.rollback()
        print(f"Password reset error: {str(e)}")
        return jsonify({'error': 'Failed to reset password'}), 500

@main.route('/verify-user')
@login_required
def verify_user_page():
    return render_template('verify_user.html')

@main.route('/api/verify-user-face', methods=['POST'])
@login_required
def verify_user_face():
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400
    
    try:
        file = request.files['image']
        image_bytes = file.read()
        
        # Check face quality first
        quality_check = face_auth.check_face_quality(image_bytes)
        if not quality_check['valid']:
            return jsonify({'error': quality_check['message']}), 400
        
        # Get all users and compare faces
        users = User.query.all()
        for user in users:
            if not user.face_encoding:
                continue
                
            stored_encoding = base64.b64decode(user.face_encoding)
            
            if face_auth.verify_face(image_bytes, stored_encoding):
                # Get all of the user's vehicles
                vehicles = Vehicle.query.filter_by(user_id=user.id).all()
                
                # Format vehicles data
                vehicles_data = []
                if vehicles:
                    for vehicle in vehicles:
                        vehicles_data.append({
                            'vehicle_number': vehicle.vehicle_number,
                            'owner_name': vehicle.owner_name,
                            'model': vehicle.model,
                            'year': vehicle.year
                        })
                
                return jsonify({
                    'success': True,
                    'user': {
                        'first_name': user.first_name,
                        'middle_name': user.middle_name,
                        'last_name': user.last_name,
                        'email': user.email,
                        'mobile_number': user.mobile_number,
                        'address': user.address,
                        'gender': user.gender,
                        'vehicles': vehicles_data  # Return all vehicles as an array
                    }
                })
    
        return jsonify({'error': 'No matching user found'}), 404
        
    except Exception as e:
        print(f"Face verification error: {str(e)}")
        return jsonify({'error': 'Face verification failed'}), 500