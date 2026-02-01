#!/usr/bin/env python3
"""
FakeICAP Database Reset Script
WARNING: This will completely reset the database and delete all data!
"""

import os
from datetime import datetime

# Reuse the main application's database initialization so that the
# schema, default settings, and admin user exactly match runtime.
from fakeicap_unified import init_db

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
    db_path = 'fakeicap.db'
    
    # Delete existing database if it exists
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            print(f"✅ Deleted existing database: {db_path}")
        except Exception as e:
            print(f"❌ Error deleting database: {e}")
            return False
    
    # Create new database with the application's schema and defaults
    try:
        # init_db() will recreate fakeicap.db with the exact tables and
        # default settings/admin user expected by fakeicap_unified.py
        init_db()

        print("✅ Database reset successfully!")
        print(f"✅ Created new database: {db_path}")
        print("✅ Created tables: users, settings, processed_files")
        print("✅ Inserted default admin user: admin/admin")
        print("✅ Inserted default settings (including ICAP/web ports, logging, and password policy)")
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
