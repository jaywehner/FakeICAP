#!/usr/bin/env python3
"""
Configuration example for FakeICAP Server
Copy this file to config.py and update with your settings
"""

# Server Configuration
SERVER_HOST = 'YOUR_SERVER_IP'  # Replace with your actual server IP address
SERVER_PORT = 1344               # Standard ICAP port

# File Storage Configuration
SAVED_FILES_DIR = 'saved_files'  # Directory to save received files
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB maximum file size
FILE_TIMEOUT = 15                # Timeout in seconds for file reception

# Logging Configuration
LOG_LEVEL = 'INFO'              # DEBUG, INFO, WARNING, ERROR
LOG_TO_FILE = True              # Enable file logging
LOG_FILE = 'icap_server.log'    # Log file name

# Security Configuration
ENABLE_FILENAME_SANITIZATION = True
ENABLE_SIZE_LIMITS = True
ENABLE_CONFLICT_RESOLUTION = True

# ICAP Protocol Configuration
ICAP_VERSION = 'ICAP/1.0'
SERVER_NAME = 'MinimalICAP/1.0'
ISTAG = '"Minimal-001"'
