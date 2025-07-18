# for user
from flask import Flask, render_template, request, jsonify, session, redirect
from app import create_app, db
from app.models.user import User
from app.models.vehicle import Vehicle
from app.utils import CryptoUtils, FaceAuth
from werkzeug.security import generate_password_hash, check_password_hash
import os
import cv2
import numpy as np
import base64
from datetime import datetime

app = create_app()
crypto_utils = CryptoUtils()
face_auth = FaceAuth()

# Create required directories
def create_upload_directories():
    upload_dirs = [
        os.path.join(app.static_folder, 'faces'),
        os.path.join(app.static_folder, 'keys'),
        os.path.join(app.static_folder, 'certificates'),
        os.path.join(app.static_folder, 'uploads')
    ]
    for directory in upload_dirs:
        os.makedirs(directory, exist_ok=True)
    
    # Set secure permissions for sensitive directories
    try:
        os.chmod(os.path.join(app.static_folder, 'keys'), 0o700)
    except Exception as e:
        print(f"Warning: Could not set directory permissions: {e}")

# Initialize database
def init_db():
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("Database tables created successfully!")
            
            # Create directories
            create_upload_directories()
            print("Upload directories created successfully!")
        except Exception as e:
            print(f"Error during initialization: {e}")

# Routes
@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
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

        # Get recent activity
        recent_activities = [
            {
                'type': 'vehicle_add',
                'description': f'Added new vehicle {vehicle.vehicle_number}',
                'timestamp': vehicle.created_at.isoformat(),
            }
            for vehicle in vehicles[-5:]  # Get last 5 vehicles
        ]

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

# Registration API
@app.route('/api/register', methods=['POST'])
def register_api():
    try:
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        face_image = request.files.get('face_image')

        if not all([username, email, password, face_image]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 400

        # Process face image
        try:
            face_image_data = face_image.read()
            face_encoding = face_auth.process_face_image(face_image_data)
            if not face_encoding:
                return jsonify({'error': 'No face detected in image'}), 400

            # Generate key pair and certificate
            private_key, public_key = crypto_utils.generate_key_pair()
            
            user_data = {
                'username': username,
                'email': email,
                'public_key': public_key
            }
            certificate = crypto_utils.generate_certificate(user_data, private_key)

            # Create user
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                public_key=public_key.decode(),
                certificate=certificate.decode(),
                face_encoding=base64.b64encode(face_encoding).decode()
            )
            
            db.session.add(user)
            db.session.commit()

            # Save private key
            key_path = os.path.join(app.static_folder, 'keys', f'{user.id}_private.pem')
            with open(key_path, 'wb') as f:
                f.write(private_key)

            return jsonify({
                'message': 'Registration successful',
                'user_id': user.id
            })

        except Exception as e:
            print(f"Error processing face: {str(e)}")
            return jsonify({'error': 'Failed to process face image'}), 500

    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

# Login API
@app.route('/api/login', methods=['POST'])
def login_api():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        face_image = request.files.get('face_image')

        if not all([username, password, face_image]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Find user
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Verify password
        if not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid password'}), 401

        # Verify face
        face_image_bytes = face_image.read()
        if not face_auth.verify_face(face_image_bytes, base64.b64decode(user.face_encoding)):
            return jsonify({'error': 'Face verification failed'}), 401

        # Create session
        session['user_id'] = user.id

        return jsonify({
            'message': 'Login successful',
            'user_id': user.id
        })

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

if __name__ == '__main__':
    # Initialize the database and create directories
    init_db()
    
    # Run the Flask application
    app.run(debug=True)
