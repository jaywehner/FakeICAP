#!/usr/bin/env python3
"""
FakeICAP Web Application Launcher
Simple script to start the web interface with proper configuration
"""

import os
import sys

def main():
    """Main launcher function"""
    print("=" * 60)
    print("FakeICAP Web Interface Launcher")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not os.path.exists('web_app.py'):
        print("Error: web_app.py not found. Please run this script from the FakeICAP directory.")
        sys.exit(1)
    
    # Check for templates directory
    if not os.path.exists('templates'):
        print("Error: templates directory not found.")
        sys.exit(1)
    
    print("Starting FakeICAP Web Interface...")
    print("Default credentials: admin / admin")
    print("Web interface will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        # Import and run the web app
        from web_app import app, init_db
        
        # Initialize database
        print("Initializing database...")
        init_db()
        print("Database initialized successfully!")
        
        # Start the Flask app
        app.run(
            debug=True,
            host='0.0.0.0',
            port=5000,
            use_reloader=False  # Prevent double initialization
        )
        
    except ImportError as e:
        print(f"Error importing web_app: {e}")
        print("Please install required dependencies:")
        print("pip install Flask Flask-Bcrypt")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting web application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
