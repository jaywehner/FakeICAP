#!/usr/bin/env python3
"""
FakeICAP Database Reset Script
WARNING: This will completely reset the database and delete all data!
"""

import os
import sqlite3
from datetime import datetime

def reset_database():
    """Reset the entire database to defaults"""
    print("=" * 60)
    print("FAKEICAP DATABASE RESET SCRIPT")
    print("=" * 60)
    print("⚠️  WARNING: This will completely reset the database!")
    print("   All data will be permanently deleted!")
    print("=" * 60)
    
    # Ask for confirmation
    confirm = input("Type 'RESET' to confirm database reset: ")
    if confirm != 'RESET':
        print("❌ Database reset cancelled.")
        return False
    
    print("\n🔄 Resetting database...")
    
    # Database file path
    db_path = 'icap.db'
    
    # Delete existing database if it exists
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            print(f"✅ Deleted existing database: {db_path}")
        except Exception as e:
            print(f"❌ Error deleting database: {e}")
            return False
    
    # Create new database with correct schema
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                must_change_password BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_default_admin BOOLEAN DEFAULT 0
            )
        ''')
        
        # Create settings table
        cursor.execute('''
            CREATE TABLE settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create processed_files table with GUID as primary key
        cursor.execute('''
            CREATE TABLE processed_files (
                id TEXT PRIMARY KEY,
                original_filename TEXT NOT NULL,
                saved_filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT,
                client_ip TEXT,
                user_agent TEXT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date_processed DATE DEFAULT CURRENT_DATE
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX idx_processed_files_date ON processed_files(date_processed)')
        cursor.execute('CREATE INDEX idx_processed_files_filename ON processed_files(original_filename)')
        
        # Insert default admin user
        from flask_bcrypt import Bcrypt
        bcrypt = Bcrypt()
        default_password = 'admin'
        hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
        
        cursor.execute('''
            INSERT INTO users (username, password, is_admin, is_default_admin)
            VALUES (?, ?, ?, ?)
        ''', ('admin', hashed_password, 1, 1))
        
        # Insert default settings
        default_settings = {
            'server_host': '10.10.0.5',
            'server_port': '1344',
            'max_file_size': '104857600',
            'log_level': 'INFO',
            'theme': 'light',
            'accent_color': 'orange',
            'log_max_bytes': '5242880',
            'log_backup_count': '10',
            'file_history_days': '30'
        }
        
        for key, value in default_settings.items():
            cursor.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (key, value))
        
        conn.commit()
        conn.close()
        
        print("✅ Database reset successfully!")
        print(f"✅ Created new database: {db_path}")
        print("✅ Created tables: users, settings, processed_files")
        print("✅ Inserted default admin user: admin/admin")
        print("✅ Inserted default settings")
        print("\n📊 Database Schema:")
        print("   - users: User accounts with GUID-based file tracking")
        print("   - settings: Configuration settings")
        print("   - processed_files: File tracking with GUID primary key")
        print("\n🔐 Default Credentials:")
        print("   Username: admin")
        print("   Password: admin")
        print("   ⚠️  Change password after first login!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        return False

def main():
    """Main function"""
    print(f"FakeICAP Database Reset - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if reset_database():
        print("\n🎉 Database reset completed successfully!")
        print("   You can now start the FakeICAP application.")
    else:
        print("\n❌ Database reset failed!")
        print("   Please check the error messages above.")

if __name__ == '__main__':
    main()
