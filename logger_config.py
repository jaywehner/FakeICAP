#!/usr/bin/env python3
"""
FakeICAP Logging Configuration
Comprehensive logging system with rotation and web interface management
"""

import os
import logging
import logging.handlers
import sqlite3
from datetime import datetime
from pathlib import Path

class FakeICAPLogger:
    def __init__(self, log_dir='logs', app_name='fakeicap'):
        self.log_dir = Path(log_dir)
        self.app_name = app_name
        self.log_dir.mkdir(exist_ok=True)
        
        # Default settings
        self.max_bytes = 5 * 1024 * 1024  # 5MB
        self.backup_count = 10
        
        # Initialize loggers
        self.setup_loggers()
        
    def setup_loggers(self):
        """Setup different loggers for different components"""
        # Main application logger
        self.app_logger = self._create_logger(
            'app', 
            'application.log',
            logging.INFO
        )
        
        # ICAP server logger
        self.icap_logger = self._create_logger(
            'icap', 
            'icap.log',
            logging.INFO
        )
        
        # Web interface logger
        self.web_logger = self._create_logger(
            'web', 
            'web.log',
            logging.INFO
        )
        
        # Security logger
        self.security_logger = self._create_logger(
            'security', 
            'security.log',
            logging.WARNING
        )
        
        # Error logger
        self.error_logger = self._create_logger(
            'error', 
            'error.log',
            logging.ERROR
        )
    
    def _setup_loggers(self):
        """Reinitialize all loggers"""
        # Clear existing handlers
        for logger_obj in [self.app_logger, self.icap_logger, self.web_logger, self.security_logger, self.error_logger]:
            logger_obj.handlers.clear()
        
        # Recreate loggers
        self.app_logger = self._create_logger(
            'app', 
            'application.log',
            logging.INFO
        )
        
        self.icap_logger = self._create_logger(
            'icap', 
            'icap.log',
            logging.INFO
        )
        
        self.web_logger = self._create_logger(
            'web', 
            'web.log',
            logging.INFO
        )
        
        self.security_logger = self._create_logger(
            'security', 
            'security.log',
            logging.WARNING
        )
        
        self.error_logger = self._create_logger(
            'error', 
            'error.log',
            logging.ERROR
        )
    
    def _create_logger(self, name, filename, level):
        """Create a logger with rotation"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Remove existing handlers
        logger.handlers.clear()
        
        # Create rotating file handler
        handler = logging.handlers.RotatingFileHandler(
            self.log_dir / filename,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # Add console handler for development
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def update_settings(self, max_bytes=None, backup_count=None):
        """Update logging settings"""
        if max_bytes:
            self.max_bytes = max_bytes
        if backup_count:
            self.backup_count = backup_count
        
        # Reinitialize loggers with new settings
        self.setup_loggers()
        
        # Log the setting change
        self.app_logger.info(f"Logging settings updated: max_bytes={self.max_bytes}, backup_count={self.backup_count}")
    
    def get_log_files(self):
        """Get list of all log files with their sizes"""
        log_files = []
        for log_file in self.log_dir.glob('*.log*'):
            if log_file.is_file():
                stat = log_file.stat()
                log_files.append({
                    'name': log_file.name,
                    'path': str(log_file),
                    'size': stat.st_size,
                    'size_human': self._format_size(stat.st_size),
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        
        # Sort by modification time (newest first)
        log_files.sort(key=lambda x: x['modified'], reverse=True)
        return log_files
    
    def _format_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0B"
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.1f}{size_names[i]}"
    
    def get_log_content(self, filename, lines=100):
        """Get content of a specific log file"""
        log_path = self.log_dir / filename
        if not log_path.exists():
            return None
        
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                # Read last N lines
                all_lines = f.readlines()
                return all_lines[-lines:] if len(all_lines) > lines else all_lines
        except Exception as e:
            self.error_logger.error(f"Error reading log file {filename}: {e}")
            return None
    
    def clear_logs(self):
        """Clear all log files"""
        try:
            # Close all handlers to release file locks
            handlers_to_close = []
            
            # Collect all handlers from all loggers
            for logger_obj in [self.app_logger, self.icap_logger, self.web_logger, self.security_logger, self.error_logger]:
                handlers_to_close.extend(logger_obj.handlers)
            
            # Close all handlers
            for handler in handlers_to_close:
                handler.close()
            
            # Wait a moment for file handles to be released
            import time
            time.sleep(0.1)
            
            # Clear all log files
            cleared_files = []
            for log_file in self.log_dir.glob('*.log*'):
                if log_file.is_file():
                    try:
                        log_file.unlink()
                        cleared_files.append(log_file.name)
                    except Exception as e:
                        # If a file can't be deleted, try to truncate it instead
                        try:
                            with open(log_file, 'w') as f:
                                f.truncate(0)
                            cleared_files.append(log_file.name + " (truncated)")
                        except Exception as e2:
                            self.error_logger.error(f"Could not clear or truncate {log_file}: {e2}")
            
            # Reinitialize logging to recreate handlers
            self._setup_loggers()
            
            if cleared_files:
                self.app_logger.info(f"Log files cleared: {', '.join(cleared_files)}")
            else:
                self.app_logger.info("No log files to clear")
            
            return True
        except Exception as e:
            self.error_logger.error(f"Error clearing logs: {e}")
            # Try to reinitialize logging even if clearing failed
            try:
                self._setup_loggers()
            except:
                pass
            return False
    
    # Convenience methods for different log types
    def log_app(self, message, level='info'):
        """Log application message"""
        getattr(self.app_logger, level)(message)
    
    def log_icap(self, message, level='info'):
        """Log ICAP server message"""
        getattr(self.icap_logger, level)(message)
    
    def log_web(self, message, level='info'):
        """Log web interface message"""
        getattr(self.web_logger, level)(message)
    
    def log_security(self, message, level='warning'):
        """Log security event"""
        getattr(self.security_logger, level)(message)
    
    def log_error(self, message, level='error'):
        """Log error"""
        getattr(self.error_logger, level)(message)

# Global logger instance
fakeicap_logger = None

def get_logger():
    """Get the global logger instance"""
    global fakeicap_logger
    if fakeicap_logger is None:
        fakeicap_logger = FakeICAPLogger()
    return fakeicap_logger

def init_logging(max_bytes=5*1024*1024, backup_count=10):
    """Initialize logging with custom settings"""
    global fakeicap_logger
    fakeicap_logger = FakeICAPLogger()
    fakeicap_logger.update_settings(max_bytes, backup_count)
    return fakeicap_logger
