import pymysql
from urllib.parse import quote_plus

def add_blockchain_fields():
    """Add blockchain-related fields to existing tables"""
    password = quote_plus('15August1947@')
    
    try:
        # Connect to database
        conn = pymysql.connect(
            host='127.0.0.1',
            user='root',
            password='15August1947@',
            database='vehicle_verification',
            port=3306
        )
        
        with conn.cursor() as cursor:
            print("Adding blockchain fields to verification_attempt table...")
            
            # Add blockchain fields to verification_attempt table
            try:
                cursor.execute("""
                    ALTER TABLE verification_attempt 
                    ADD COLUMN blockchain_hash VARCHAR(66),
                    ADD COLUMN block_number INTEGER,
                    ADD COLUMN blockchain_verified BOOLEAN DEFAULT FALSE
                """)
                print("✅ Added blockchain fields to verification_attempt")
            except Exception as e:
                if "Duplicate column name" in str(e):
                    print("⚠️  Blockchain fields already exist in verification_attempt")
                else:
                    print(f"❌ Error adding fields to verification_attempt: {e}")
            
            print("Adding blockchain fields to vehicle table...")
            
            # Add blockchain fields to vehicle table
            try:
                cursor.execute("""
                    ALTER TABLE vehicle 
                    ADD COLUMN blockchain_record VARCHAR(66),
                    ADD COLUMN last_blockchain_update DATETIME
                """)
                print("✅ Added blockchain fields to vehicle")
            except Exception as e:
                if "Duplicate column name" in str(e):
                    print("⚠️  Blockchain fields already exist in vehicle")
                else:
                    print(f"❌ Error adding fields to vehicle: {e}")
            
            print("Adding blockchain fields to vehicle_certificate table...")
            
            # Add blockchain fields to vehicle_certificate table (if it exists)
            try:
                cursor.execute("""
                    ALTER TABLE vehicle_certificate 
                    ADD COLUMN certificate_hash VARCHAR(66),
                    ADD COLUMN blockchain_transaction VARCHAR(66)
                """)
                print("✅ Added blockchain fields to vehicle_certificate")
            except Exception as e:
                if "Duplicate column name" in str(e):
                    print("⚠️  Blockchain fields already exist in vehicle_certificate")
                elif "doesn't exist" in str(e):
                    print("⚠️  vehicle_certificate table doesn't exist yet")
                else:
                    print(f"❌ Error adding fields to vehicle_certificate: {e}")
            
            # Commit changes
            conn.commit()
            print("\n🎉 Blockchain fields migration completed successfully!")
            
    except Exception as e:
        print(f"❌ Database connection error: {str(e)}")
    finally:
        if 'conn' in locals() and conn.open:
            conn.close()

if __name__ == "__main__":
    add_blockchain_fields()