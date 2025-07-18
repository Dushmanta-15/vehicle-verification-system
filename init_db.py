# init_database.py
import pymysql
from urllib.parse import quote_plus

def init_database():
    password = quote_plus('15August1947@')
    
    try:
        # Connect without database
        conn = pymysql.connect(
            host='127.0.0.1',
            user='root',
            password='15August1947@',
            port=3306
        )
        
        with conn.cursor() as cursor:
            # Create database
            cursor.execute("CREATE DATABASE IF NOT EXISTS vehicle_verification")
            print("Database created or already exists")
            
            # Use the database
            cursor.execute("USE vehicle_verification")
            
            # Create admin table (keeping your existing table)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admin (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(80) UNIQUE NOT NULL,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    last_login DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("Admin table created")

            # Create user table with all required columns
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(80) UNIQUE NOT NULL,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    first_name VARCHAR(50) NOT NULL,
                    middle_name VARCHAR(50),
                    last_name VARCHAR(50) NOT NULL,
                    mobile_number VARCHAR(15) NOT NULL,
                    address TEXT NOT NULL,
                    gender VARCHAR(10) NOT NULL,
                    public_key TEXT,
                    certificate TEXT,
                    face_encoding TEXT,
                    last_login DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME ON UPDATE CURRENT_TIMESTAMP,
                    reset_token VARCHAR(100),
                    reset_token_expiry DATETIME
                )
            """)
            print("User table created")

            # Create vehicle table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vehicle (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    vehicle_number VARCHAR(20) UNIQUE NOT NULL,
                    owner_name VARCHAR(100) NOT NULL,
                    model VARCHAR(100),
                    year INT,
                    encrypted_details TEXT,
                    digital_signature TEXT,
                    qr_code TEXT,
                    user_id INT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
                )
            """)
            print("Vehicle table created")
            
            # Update authentication
            cursor.execute("""
                ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY %s
            """, ('15August1947@',))
            
            # Set privileges
            cursor.execute("GRANT ALL PRIVILEGES ON vehicle_verification.* TO 'root'@'localhost'")
            cursor.execute("FLUSH PRIVILEGES")
            print("Privileges updated")
            
        conn.commit()
        print("Database initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
    finally:
        if 'conn' in locals() and conn.open:
            conn.close()

if __name__ == "__main__":
    init_database()