#!/usr/bin/env python3
"""
FakeICAP Unified Application Launcher
Simple script to start the unified ICAP + Web application
"""

import os
import sys

def main():
    """Main launcher function"""
    print("=" * 60)
    print("FakeICAP Unified Application Launcher")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not os.path.exists('fakeicap_unified.py'):
        print("Error: fakeicap_unified.py not found. Please run this script from the FakeICAP directory.")
        sys.exit(1)
    
    # Check for templates directory
    if not os.path.exists('templates'):
        print("Error: templates directory not found.")
        sys.exit(1)
    
    print("Starting FakeICAP Unified Application...")
    print("This includes both the ICAP server and web interface")
    print("Default credentials: admin / admin")
    print("Web interface: http://localhost:5000")
    print("ICAP server: YOUR_SERVER_IP:1344")
    print("Press Ctrl+C to stop both services")
    print("=" * 60)
    
    try:
        # Import and run the unified app
        from fakeicap_unified import main as run_unified_app
        run_unified_app()
        
    except ImportError as e:
        print(f"Error importing unified app: {e}")
        print("Please install required dependencies:")
        print("pip install Flask Flask-Bcrypt")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting unified application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
