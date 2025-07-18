# create_admin.py
from app import create_app, db
from app.models.admin import Admin
from werkzeug.security import generate_password_hash

def create_admin():
    app = create_app()
    
    with app.app_context():
        # Check if admin exists
        if Admin.query.filter_by(username='admin').first():
            print("Admin user already exists!")
            return

        # Create admin user
        admin = Admin(
            username='admin',
            email='admin@yourdomain.com',
            password_hash=generate_password_hash('admin123')  # Change this password!
        )

        try:
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {str(e)}")

if __name__ == "__main__":
    create_admin()