#!/usr/bin/env python3
"""
FakeICAP Web Frontend
Flask web application with user authentication and management
"""

import os
import sqlite3
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_bcrypt import Bcrypt
from logger_config import get_logger, init_logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
bcrypt = Bcrypt(app)

# Database configuration
DB_NAME = 'fakeicap_web.db'

def init_db():
    """Initialize the SQLite database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
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
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check if default admin exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        # Create default admin account
        hashed_password = bcrypt.generate_password_hash('admin').decode('utf-8')
        cursor.execute('''
            INSERT INTO users (username, password, is_admin, must_change_password, is_default_admin)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', hashed_password, 1, 1, 1))
    
    # Insert default settings
    default_settings = {
        'server_host': 'YOUR_SERVER_IP',
        'server_port': '1344',
        'max_file_size': '52428800',  # 50MB
        'file_timeout': '15',
        'theme': 'light',
        'accent_color': 'orange',
        'log_max_bytes': '5242880',   # 5MB
        'log_backup_count': '10'
    }
    
    for key, value in default_settings.items():
        cursor.execute('''
            INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)
        ''', (key, value))
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    """Login required decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Admin required decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Redirect to dashboard or login"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            session['must_change_password'] = user['must_change_password']
            
            # Update last login
            conn = get_db_connection()
            conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
            conn.commit()
            conn.close()
            
            # Log successful login
            logger = get_logger()
            logger.log_security(f"User '{username}' logged in successfully from {request.remote_addr}")
            
            if user['must_change_password']:
                flash('You must change your password before continuing', 'warning')
                return redirect(url_for('change_password'))
            
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Log failed login attempt
            logger = get_logger()
            logger.log_security(f"Failed login attempt for user '{username}' from {request.remote_addr}")
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('register.html')
        
        conn = get_db_connection()
        
        # Check if username exists
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            conn.close()
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        # Create new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        conn.execute('''
            INSERT INTO users (username, password, is_admin, must_change_password)
            VALUES (?, ?, ?, ?)
        ''', (username, hashed_password, 0, 0))
        
        conn.commit()
        conn.close()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    if session.get('must_change_password'):
        return redirect(url_for('change_password'))
    
    conn = get_db_connection()
    
    # Get current settings
    settings = conn.execute('SELECT key, value FROM settings').fetchall()
    settings_dict = {row['key']: row['value'] for row in settings}
    
    # Get server status (mock for now)
    server_status = {
        'running': True,
        'uptime': '2 hours 15 minutes',
        'files_processed': 42,
        'last_file': 'goanywhere.log'
    }
    
    conn.close()
    
    return render_template('dashboard.html', 
                         settings=settings_dict, 
                         server_status=server_status,
                         theme=settings_dict.get('theme', 'light'),
                         current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_password or not new_password:
            flash('All fields are required', 'error')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('change_password.html')
        
        conn = get_db_connection()
        user = conn.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if not bcrypt.check_password_hash(user['password'], current_password):
            conn.close()
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')
        
        # Update password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        conn.execute('''
            UPDATE users 
            SET password = ?, must_change_password = 0 
            WHERE id = ?
        ''', (hashed_password, session['user_id']))
        
        conn.commit()
        conn.close()
        
        session['must_change_password'] = 0
        flash('Password changed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/users')
@admin_required
def users():
    """Users management page"""
    conn = get_db_connection()
    users_list = conn.execute('''
        SELECT id, username, is_admin, must_change_password, created_at, last_login, is_default_admin
        FROM users 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('users.html', users=users_list)

@app.route('/add_user', methods=['POST'])
@admin_required
def add_user():
    """Add new user"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    is_admin = request.form.get('is_admin') == 'on'
    must_change_password = request.form.get('must_change_password') == 'on'
    
    if not username or not password:
        flash('Username and password are required', 'error')
        return redirect(url_for('users'))
    
    if len(password) < 6:
        flash('Password must be at least 6 characters long', 'error')
        return redirect(url_for('users'))
    
    conn = get_db_connection()
    
    # Check if username exists
    existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing_user:
        conn.close()
        flash('Username already exists', 'error')
        return redirect(url_for('users'))
    
    # Create new user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    conn.execute('''
        INSERT INTO users (username, password, is_admin, must_change_password)
        VALUES (?, ?, ?, ?)
    ''', (username, hashed_password, is_admin, must_change_password))
    
    conn.commit()
    conn.close()
    
    flash(f'User {username} created successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    """Delete user"""
    conn = get_db_connection()
    user = conn.execute('SELECT username, is_default_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('users'))
    
    if user['is_default_admin']:
        conn.close()
        flash('Cannot delete default admin account', 'error')
        return redirect(url_for('users'))
    
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash(f'User {user["username"]} deleted successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/reset_user_password/<int:user_id>', methods=['POST'])
@admin_required
def reset_user_password(user_id):
    """Reset user password"""
    new_password = request.form.get('new_password', '')
    must_change_password = request.form.get('must_change_password') == 'on'
    
    if not new_password:
        flash('Password is required', 'error')
        return redirect(url_for('users'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters long', 'error')
        return redirect(url_for('users'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('users'))
    
    # Update password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    conn.execute('''
        UPDATE users 
        SET password = ?, must_change_password = ? 
        WHERE id = ?
    ''', (hashed_password, must_change_password, user_id))
    
    conn.commit()
    conn.close()
    
    flash(f'Password for {user["username"]} reset successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    """Update application settings"""
    settings = {
        'server_host': request.form.get('server_host', 'YOUR_SERVER_IP'),
        'server_port': request.form.get('server_port', '1344'),
        'max_file_size': request.form.get('max_file_size', '52428800'),
        'file_timeout': request.form.get('file_timeout', '15'),
        'theme': request.form.get('theme', 'light'),
        'accent_color': request.form.get('accent_color', 'orange'),
        'log_max_bytes': request.form.get('log_max_bytes', '5242880'),
        'log_backup_count': request.form.get('log_backup_count', '10')
    }
    
    conn = get_db_connection()
    for key, value in settings.items():
        conn.execute('''
            INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (key, value))
    
    conn.commit()
    conn.close()
    
    # Update logging settings if they changed
    logger = get_logger()
    logger.update_settings(
        max_bytes=int(settings['log_max_bytes']),
        backup_count=int(settings['log_backup_count'])
    )
    
    flash('Settings updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logs')
@login_required
def logs():
    """Logs page"""
    logger = get_logger()
    log_files = logger.get_log_files()
    
    # Get current settings
    conn = get_db_connection()
    settings_data = conn.execute('SELECT key, value FROM settings').fetchall()
    settings_dict = {row['key']: row['value'] for row in settings_data}
    conn.close()
    
    # Calculate statistics in Python instead of template
    stats = {
        'total_files': len(log_files),
        'total_size_mb': sum(f['size'] for f in log_files) / 1048576,
        'error_logs': len([f for f in log_files if 'error' in f['name']]),
        'security_logs': len([f for f in log_files if 'security' in f['name']]),
        'icap_logs': len([f for f in log_files if 'icap' in f['name']]),
        'web_logs': len([f for f in log_files if 'web' in f['name']]),
        'app_logs': len([f for f in log_files if 'app' in f['name'] and not any(x in f['name'] for x in ['error', 'security', 'icap', 'web'])])
    }
    
    return render_template('logs.html', log_files=log_files, stats=stats, settings=settings_dict)

@app.route('/logs/view/<filename>')
@login_required
def view_log(filename):
    """View specific log file content"""
    logger = get_logger()
    log_content = logger.get_log_content(filename, lines=200)
    
    if log_content is None:
        flash('Log file not found', 'error')
        return redirect(url_for('logs'))
    
    # Calculate statistics in Python instead of template
    content_text = ''.join(log_content)
    stats = {
        'total_lines': len(log_content),
        'error_count': content_text.count('ERROR'),
        'warning_count': content_text.count('WARNING'),
        'info_count': content_text.count('INFO')
    }
    
    return render_template('log_view.html', 
                         filename=filename, 
                         log_content=log_content,
                         stats=stats)

@app.route('/logs/download/<filename>')
@login_required
def download_log(filename):
    """Download log file"""
    logger = get_logger()
    log_path = logger.log_dir / filename
    
    if not log_path.exists():
        flash('Log file not found', 'error')
        return redirect(url_for('logs'))
    
    return send_file(log_path, as_attachment=True)

@app.route('/logs/clear', methods=['POST'])
@admin_required
def clear_logs():
    """Clear all log files"""
    logger = get_logger()
    if logger.clear_logs():
        flash('All log files cleared successfully', 'success')
    else:
        flash('Error clearing log files', 'error')
    
    return redirect(url_for('logs'))

if __name__ == '__main__':
    init_db()
    
    # Initialize logging with default settings
    logger = get_logger()
    logger.log_app("FakeICAP Web Interface starting up")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
