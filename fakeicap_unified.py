#!/usr/bin/env python3

import socket
import threading
import os
import sys
import hashlib
import uuid
import datetime
import sqlite3
import time
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Add the current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our logger
from logger_config import get_logger

# Global variables
logger = None
icap_server_running = False
icap_server_socket = None

# Global dictionary to track ongoing file transfers
ongoing_transfers = {}

# Timeout for incomplete transfers (in seconds)
TRANSFER_TIMEOUT = 5  # 5 seconds - save quickly since GoAnywhere might not send more chunks

def cleanup_incomplete_transfers():
    """Clean up incomplete transfers that have timed out"""
    current_time = datetime.datetime.now()
    completed_transfers = []
    
    print(f"Checking {len(ongoing_transfers)} transfers for timeouts...")
    
    for transfer_key, transfer_data in ongoing_transfers.items():
        # Check if transfer has timed out
        time_since_last_activity = (current_time - transfer_data['last_activity']).total_seconds()
        print(f"Transfer {transfer_key}: last activity {time_since_last_activity:.1f} seconds ago")
        
        if time_since_last_activity > TRANSFER_TIMEOUT:
            print(f"Transfer timeout for {transfer_key} - saving incomplete content")
            
            # Save the incomplete content
            try:
                file_content = bytes(transfer_data['content'])
                file_info = transfer_data['file_info']
                client_address = transfer_data.get('client_address')
                
                print(f"Saving incomplete transfer: {len(file_content)} bytes")
                file_path, record_path = save_file_and_record(file_info, file_content, client_address, force_save=True)
                if file_path and record_path:
                    print(f"Successfully saved incomplete transfer: {file_info.get('filename', 'unknown')}")
                else:
                    print(f"Failed to save incomplete transfer: {file_info.get('filename', 'unknown')}")
                
                completed_transfers.append(transfer_key)
            except Exception as e:
                print(f"Error saving incomplete transfer {transfer_key}: {e}")
                completed_transfers.append(transfer_key)
    
    # Remove completed transfers
    for transfer_key in completed_transfers:
        del ongoing_transfers[transfer_key]
        
    if completed_transfers:
        print(f"Cleaned up {len(completed_transfers)} timed out transfers")

def get_server_host():
    """Get server host from config or use default"""
    try:
        import config
        return getattr(config, 'ICAP_HOST', '10.10.0.5')
    except ImportError:
        return '10.10.0.5'

def get_server_port():
    """Get server port from config or use default"""
    try:
        import config
        return getattr(config, 'ICAP_PORT', 1344)
    except ImportError:
        return 1344

def create_directory_structure(date_str):
    """Create date-based directory structure for saving files"""
    try:
        base_path = 'saved_files'
        dir_path = os.path.join(base_path, date_str)
        
        # Create directories if they don't exist
        os.makedirs(dir_path, exist_ok=True)
        
        print(f"Created/verified directory structure: {dir_path}")
        return dir_path
        
    except Exception as e:
        print(f"Error creating directory structure: {e}")
        return base_path

def sanitize_filename(filename):
    """Sanitize filename to prevent security issues"""
    if not filename:
        return "unknown_file"
    
    # Remove path separators and dangerous characters
    filename = filename.replace('/', '_').replace('\\', '_')
    filename = filename.replace('<', '_').replace('>', '_')
    filename = filename.replace(':', '_').replace('"', '_')
    filename = filename.replace('|', '_').replace('?', '_')
    filename = filename.replace('*', '_')
    
    # Limit length
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:95] + ext
    
    return filename.strip()

def get_transfer_key(file_info, client_address):
    """Generate a unique key for a file transfer"""
    return f"{client_address[0]}:{file_info.get('filename', 'unknown')}"

def parse_encapsulated_header(data_str):
    """Parse the Encapsulated header according to RFC 3507"""
    try:
        lines = data_str.split('\r\n')
        for line in lines:
            if line.startswith('Encapsulated:'):
                encapsulated = line[12:].strip()
                logger.icap_logger.info(f"Found Encapsulated header: {encapsulated}")
                return encapsulated
        return None
    except Exception as e:
        logger.icap_logger.error(f"Error parsing Encapsulated header: {e}")
        return None

def decode_chunked_body(body):
    """Decode an HTTP chunked-encoding body.

    Returns decoded bytes if the body looks like valid chunked data,
    otherwise returns None and the caller should treat it as a normal body.
    """
    try:
        i = 0
        n = len(body)
        decoded = bytearray()

        while True:
            # Find next CRLF with chunk size line
            line_end = body.find(b"\r\n", i)
            if line_end == -1:
                return None

            size_line = body[i:line_end]
            # Allow optional chunk extensions after ';'
            size_token = size_line.split(b";", 1)[0].strip()
            if not size_token:
                return None

            try:
                chunk_size = int(size_token, 16)
            except ValueError:
                # Not a valid hex size -> not chunked
                return None

            i = line_end + 2  # skip CRLF

            if chunk_size == 0:
                # Last chunk. There may be optional trailer headers terminated
                # by CRLF-CRLF; we ignore any remaining bytes.
                break

            # Ensure we have the full chunk payload
            if i + chunk_size > n:
                return None

            decoded.extend(body[i:i + chunk_size])
            i += chunk_size

            # Each chunk data must be followed by CRLF
            if i + 2 > n or body[i:i + 2] != b"\r\n":
                return None
            i += 2

        return bytes(decoded)
    except Exception as e:
        logger.icap_logger.error(f"Error decoding chunked body: {e}")
        return None

def extract_encapsulated_content(data, encapsulated_header):
    """Extract content based on Encapsulated header according to RFC 3507"""
    try:
        if not encapsulated_header:
            logger.icap_logger.error("No Encapsulated header found")
            return None
        
        # Parse the encapsulated header
        # Format: req-body=0, res-body=1234, null-body=0
        parts = encapsulated_header.split(',')
        offsets = {}
        
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                offsets[key.strip()] = int(value.strip())
        
        logger.icap_logger.info(f"Parsed encapsulated offsets: {offsets}")
        
        # Find the content we want
        content_offset = None
        content_type = None
        
        if 'req-body' in offsets:
            content_offset = offsets['req-body']
            content_type = 'req-body'
        elif 'res-body' in offsets:
            content_offset = offsets['res-body']
            content_type = 'res-body'
        elif 'null-body' in offsets:
            # No content to process
            logger.icap_logger.info("Null-body request - no content to process")
            return None
        
        if content_offset is None:
            logger.icap_logger.error("No body content found in encapsulated header")
            return None
        
        # Find the end of ICAP headers (double CRLF)
        header_end = data.find(b'\r\n\r\n')
        if header_end == -1:
            logger.icap_logger.error("Could not find end of ICAP headers")
            return None
        
        # Calculate the actual start of the content
        # The offset is relative to the start of the encapsulated message
        # which is right after the ICAP headers
        content_start = header_end + 4 + content_offset
        
        if content_start >= len(data):
            logger.icap_logger.error(f"Content offset {content_offset} is beyond data length")
            return None
        
        # Extract the raw content (this may be a chunked-encoded HTTP body)
        content = data[content_start:]
        
        logger.icap_logger.info(f"Extracted {len(content)} bytes of {content_type} content")
        logger.icap_logger.info(f"Content starts with (hex): {content[:50].hex()}")
        logger.icap_logger.info(f"Content starts with (text): {content[:50]}")
        
        # First, try to decode standard HTTP chunked transfer encoding. This is
        # fully format-agnostic and preserves the exact body bytes.
        decoded = decode_chunked_body(content)
        if decoded is not None:
            logger.icap_logger.info(
                f"Decoded HTTP chunked body: {len(content)} -> {len(decoded)} bytes"
            )
            content = decoded
        else:
            logger.icap_logger.info(
                "Content does not appear to be valid HTTP chunked body; using raw content"
            )

            # Fallback: handle legacy GoAnywhere '2000' prefix at the very start only.
            # This avoids global search/replace that could corrupt legitimate data.
            if content.startswith(b'2000'):
                logger.icap_logger.warning(
                    "⚠️ Content starts with '2000' - removing GoAnywhere prefix from start of body"
                )
                content = content[4:]
                while content.startswith(b'\r\n') or content.startswith(b'\n') or content.startswith(b'\r'):
                    content = content[2:] if content.startswith(b'\r\n') else content[1:]
        
        logger.icap_logger.info(f"Clean content: {len(content)} bytes")
        logger.icap_logger.info(f"Clean content starts with (hex): {content[:50].hex()}")
        logger.icap_logger.info(f"Clean content starts with (text): {content[:50]}")
        logger.icap_logger.info(f"Clean content ends with (hex): {content[-50:].hex()}")
        
        return content
        
    except Exception as e:
        logger.icap_logger.error(f"Error extracting encapsulated content: {e}")
        return None

def extract_file_info_from_icap(data):
    """Extract file information from ICAP request headers"""
    try:
        data_str = data.decode('utf-8', errors='ignore')
        logger.icap_logger.info(f"ICAP request received: {data_str[:200]}...")
        
        file_info = {
            'method': '',
            'filename': '',
            'content_length': 0,
            'path': '',
            'host': ''
        }
        
        # Parse ICAP request line
        lines = data_str.split('\r\n')
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                file_info['method'] = parts[0]
                logger.icap_logger.info(f"ICAP method: {parts[0]}")
        
        # Look for file information in the encapsulated HTTP request/response
        in_http_request = False
        in_http_response = False
        
        for line in lines:
            line = line.strip()
            
            # Detect HTTP request
            if line.startswith('GET ') or line.startswith('POST '):
                in_http_request = True
                # Extract filename from GET/POST line
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[1]
                    file_info['path'] = path
                    # Extract filename from path
                    if '/' in path:
                        filename = path.split('/')[-1]
                        file_info['filename'] = filename
                continue
            
            # Detect HTTP response
            elif line.startswith('HTTP/1.1 200 OK'):
                in_http_response = True
                continue
            
            # Parse headers in HTTP request or response
            if in_http_request or in_http_response:
                if ':' in line:
                    header_name, header_value = line.split(':', 1)
                    header_name = header_name.strip().lower()
                    header_value = header_value.strip()
                    
                    if header_name == 'content-length':
                        try:
                            file_info['content_length'] = int(header_value)
                            logger.icap_logger.info(f"Found Content-Length: {header_value}")
                        except ValueError:
                            logger.icap_logger.warning(f"Invalid Content-Length: {header_value}")
                    elif header_name == 'host' and not file_info['host']:
                        file_info['host'] = header_value
                        logger.icap_logger.info(f"Found Host: {header_value}")
                    elif header_name == 'content-disposition':
                        # Extract filename from Content-Disposition header
                        if 'filename=' in header_value:
                            filename_part = header_value.split('filename=')[1].strip()
                            # Remove quotes if present
                            if filename_part.startswith('"') and filename_part.endswith('"'):
                                filename_part = filename_part[1:-1]
                            file_info['filename'] = filename_part
                            logger.icap_logger.info(f"Found filename in Content-Disposition: {filename_part}")
                elif line == '':  # End of HTTP headers
                    break
        
        logger.icap_logger.info(f"Extracted file info: {file_info}")
        return file_info
    except Exception as e:
        logger.icap_logger.error(f"Error extracting file info: {e}")
        return None

def save_file_and_record(file_info, file_content, client_address=None, user_agent=None, force_save=False):
    """Save both the file and its record using the same GUID, with chunk support"""
    try:
        print(f"=== save_file_and_record called ===")
        print(f"file_info: {file_info}")
        print(f"file_content length: {len(file_content) if file_content else 'None'}")
        print(f"client_address: {client_address}")
        print(f"user_agent: {user_agent}")
        print(f"force_save: {force_save}")
        
        if not file_info or not file_content:
            print("Missing file info or content")
            return None, None
        
        # Get filename from file info
        original_filename = file_info.get('filename', 'unknown_file')
        if not original_filename:
            original_filename = "unknown_file"
        
        print(f"Original filename from ICAP: '{original_filename}'")
        print(f"File content length: {len(file_content)} bytes")
        
        # Check if this might be a chunk of an ongoing transfer
        transfer_key = get_transfer_key(file_info, client_address)
        print(f"Transfer key: {transfer_key}")
        print(f"Ongoing transfers: {list(ongoing_transfers.keys())}")
        
        # If force_save is True, skip chunked transfer logic and save immediately
        if force_save:
            print("Force save enabled - skipping chunked transfer logic")
        else:
            # Always check for ongoing transfers (even if content_length is 0)
            if transfer_key in ongoing_transfers:
                print(f"Found ongoing transfer for {transfer_key}")
                # This is another chunk - append to existing content
                try:
                    ongoing_transfers[transfer_key]['content'].extend(file_content)
                    ongoing_transfers[transfer_key]['chunks_received'] += 1
                    ongoing_transfers[transfer_key]['last_activity'] = datetime.datetime.now()
                    
                    print(f"Appended chunk {ongoing_transfers[transfer_key]['chunks_received']} ({len(file_content)} bytes)")
                    print(f"Total content so far: {len(ongoing_transfers[transfer_key]['content'])} bytes")
                    
                    # Check if content size matches expected (from Content-Length if available)
                    expected_size = file_info.get('content_length', 0)
                    if expected_size > 0 and len(ongoing_transfers[transfer_key]['content']) >= expected_size:
                        # Transfer complete - use the accumulated content
                        file_content = bytes(ongoing_transfers[transfer_key]['content'])
                        print(f"Transfer complete: {len(file_content)} bytes total")
                        del ongoing_transfers[transfer_key]
                    else:
                        # More content expected - don't save yet
                        print("Waiting for more content...")
                        return None, None
                except Exception as e:
                    print(f"Error appending to chunked transfer: {e}")
                    # Fall through to treat as new file
            else:
                print(f"No ongoing transfer found for {transfer_key}")
                # Check if this looks like it might be a chunk (even without content_length)
                # Heuristic: if content is small and we expect larger files, treat as potentially chunked
                expected_size = file_info.get('content_length', 0)
                print(f"Expected size: {expected_size}, actual size: {len(file_content)}")
                
                # Always treat as potentially chunked if we expect larger content
                # or if the content seems incomplete (ends mid-sentence for text files)
                should_treat_as_chunked = False
                
                if expected_size > 0 and len(file_content) < expected_size:
                    should_treat_as_chunked = True
                    print(f"Expected {expected_size} bytes but got {len(file_content)} - treating as chunked")
                elif expected_size == 0 and len(file_content) > 500:
                    # Lower threshold - treat files >500 bytes as potentially chunked
                    should_treat_as_chunked = True
                    print(f"File ({len(file_content)} bytes) with no content-length - treating as potentially chunked")
                elif len(file_content) > 1000:
                    # Any file over 1000 bytes should be treated as potentially chunked
                    should_treat_as_chunked = True
                    print(f"Large file ({len(file_content)} bytes) - treating as potentially chunked")
                
                print(f"Should treat as chunked: {should_treat_as_chunked}")
                
                if should_treat_as_chunked:
                    # This is likely the first chunk of a multi-chunk transfer
                    print(f"Creating new chunked transfer for {transfer_key}")
                    try:
                        ongoing_transfers[transfer_key] = {
                            'file_info': file_info,
                            'content': bytearray(file_content),
                            'chunks_received': 1,
                            'start_time': datetime.datetime.now(),
                            'last_activity': datetime.datetime.now(),
                            'client_address': client_address
                        }
                        print(f"Started chunked transfer: {len(file_content)} bytes received")
                        return None, None
                    except Exception as e:
                        print(f"Error creating chunked transfer: {e}")
                        # Fall through to treat as complete single-chunk file
                        print("Falling back to single-chunk file save")
        
        # Sanitize filename
        sanitized_filename = sanitize_filename(original_filename)
        print(f"Sanitized filename: '{sanitized_filename}'")
        
        # Create date-based directory structure
        date_str = datetime.datetime.now().strftime('%Y/%m/%d')
        dir_path = create_directory_structure(date_str)
        
        # Generate GUID for this file
        shared_guid = str(uuid.uuid4())
        print(f"Generated GUID: {shared_guid}")
        
        # Create filenames
        safe_filename = f"{shared_guid}_{sanitized_filename}"
        file_filename = safe_filename
        record_filename = f"record_{shared_guid}.txt"
        
        print(f"Final saved filename will be: {safe_filename}")
        
        # Full file paths
        file_path = os.path.join(dir_path, file_filename)
        record_path = os.path.join(dir_path, record_filename)
        
        # Calculate file hash
        file_hash = hashlib.sha256(file_content).hexdigest()
        print(f"File hash: {file_hash}")
        
        # Save the actual file
        with open(file_path, 'wb') as f:
            f.write(file_content)
        print(f"File saved successfully: {file_path} ({len(file_content)} bytes)")
        
        # Create and save record file
        record_content = f"""File Record
==========
GUID: {shared_guid}
Original Filename: {original_filename}
Saved Filename: {file_filename}
File Size: {len(file_content)} bytes
File Hash (SHA256): {file_hash}
Client IP: {client_address[0] if client_address else 'Unknown'}
User Agent: {user_agent or 'Unknown'}
Processed At: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Date Processed: {datetime.datetime.now().strftime('%Y-%m-%d')}
"""
        
        with open(record_path, 'w', encoding='utf-8') as f:
            f.write(record_content)
        print(f"Record saved successfully: {record_path}")
        
        # Insert into database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO processed_files 
            (id, original_filename, saved_filename, file_size, file_hash, client_ip, user_agent, processed_at, date_processed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (shared_guid, original_filename, file_filename, len(file_content), file_hash, 
              client_address[0] if client_address else None, user_agent, 
              datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), datetime.datetime.now().strftime('%Y-%m-%d')))
        
        conn.commit()
        conn.close()
        
        print("Database record inserted")
        print(f"Successfully saved file and record with matching GUIDs")
        
        return file_path, record_path
        
    except Exception as e:
        print(f"Error in save_file_and_record: {e}")
        return None, None

def get_db_connection():
    """Get database connection"""
    try:
        conn = sqlite3.connect('fakeicap.db')
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

def init_db():
    """Initialize database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create processed_files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_files (
                id TEXT PRIMARY KEY,
                original_filename TEXT NOT NULL,
                saved_filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                client_ip TEXT,
                user_agent TEXT,
                processed_at TEXT NOT NULL,
                date_processed TEXT NOT NULL
            )
        ''')
        
        # Create settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        
        # Insert default settings
        cursor.execute('''
            INSERT OR IGNORE INTO settings (key, value) VALUES 
            ('icap_host', '10.10.0.5'),
            ('icap_port', '1344'),
            ('web_host', 'localhost'),
            ('web_port', '5000')
        ''')
        
        conn.commit()
        conn.close()
        print("Database initialized successfully")
        
    except Exception as e:
        print(f"Error initializing database: {e}")

def get_current_gmt_time():
    """Get current GMT time in ICAP format"""
    return datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

def handle_icap_client(client_socket, client_address):
    """Handle ICAP client connection using proper RFC 3507 protocol"""
    global logger
    
    try:
        logger.icap_logger.info(f"=== ICAP CONNECTION from {client_address} ===")
        
        # Set a reasonable timeout for receiving ICAP request
        client_socket.settimeout(30.0)  # Allow more time for large files
        
        # Receive the complete ICAP request (including HTTP body).
        # We read until the client closes the connection or we hit a
        # generous safety limit to avoid unbounded memory growth.
        MAX_ICAP_REQUEST_SIZE = 50 * 1024 * 1024  # 50 MB safety cap
        data = b""
        while True:
            try:
                chunk = client_socket.recv(8192)
                if not chunk:
                    break
                data += chunk

                if len(data) > MAX_ICAP_REQUEST_SIZE:
                    logger.icap_logger.warning(
                        f"Reached MAX_ICAP_REQUEST_SIZE ({MAX_ICAP_REQUEST_SIZE} bytes); truncating ICAP request"
                    )
                    break
            except socket.timeout:
                logger.icap_logger.warning("Timeout receiving ICAP request")
                break

        logger.icap_logger.info(f"Finished receiving ICAP data: {len(data)} bytes total")
        
        if not data:
            logger.icap_logger.warning("No data received from ICAP client")
            return
        
        logger.icap_logger.info(f"Received {len(data)} bytes from ICAP client")
        logger.icap_logger.info(f"ICAP request preview: {data[:200]}...")
        
        # Parse the ICAP request
        data_str = data.decode('utf-8', errors='ignore')
        
        if 'OPTIONS' in data_str:
            # Respond to OPTIONS request
            response = f"""ICAP/1.0 200 OK\r
Date: {get_current_gmt_time()}\r
Server: FakeICAP/1.0\r
Connection: close\r
ISTag: "FakeICAP-001"\r
Methods: REQMOD, RESPMOD, OPTIONS\r
Allow: 204\r
Service: FakeICAP/1.0 "Fake ICAP Server"\r
Encapsulated: null-body=0\r
\r
\r
""".encode('utf-8')
            client_socket.send(response)
            logger.icap_logger.info("Sent OPTIONS response")
            return
            
        elif 'RESPMOD' in data_str:
            # Handle RESPMOD request
            logger.icap_logger.info("Processing RESPMOD request")
            
            # Parse the Encapsulated header
            encapsulated_header = parse_encapsulated_header(data_str)
            
            if encapsulated_header:
                # Try to extract the encapsulated content
                file_content = extract_encapsulated_content(data, encapsulated_header)
                
                if file_content:
                    # We got file content - process it normally
                    logger.icap_logger.info(f"Extracted {len(file_content)} bytes of content")
                    
                    # Extract file information from the encapsulated HTTP headers
                    file_info = extract_file_info_from_icap(data)
                    
                    if file_info and file_info.get('filename'):
                        logger.icap_logger.info(f"Processing file: {file_info['filename']} ({len(file_content)} bytes)")
                        
                        # Save the file. At this point we have the full HTTP
                        # entity body (including any chunked decoding already
                        # handled in extract_encapsulated_content), so we can
                        # safely force an immediate save without treating this
                        # as a multi-part transfer.
                        file_path, record_path = save_file_and_record(
                            file_info, file_content, client_address, force_save=True
                        )
                        if file_path and record_path:
                            logger.icap_logger.info(f"Successfully saved file: {file_info['filename']}")
                        elif file_path is None and record_path is None:
                            # This is likely a chunked transfer - don't treat as error
                            logger.icap_logger.info(f"File transfer in progress for: {file_info['filename']}")
                        else:
                            logger.icap_logger.error(f"Failed to save file: {file_info['filename']}")
                    else:
                        logger.icap_logger.warning("Could not extract file information")
                else:
                    # No content extracted - this is virus scanning mode
                    logger.icap_logger.warning("No file content extracted - virus scanning mode detected")
                    
                    # Extract file information from the encapsulated HTTP headers
                    file_info = extract_file_info_from_icap(data)
                    
                    if file_info and file_info.get('filename'):
                        logger.icap_logger.info(f"Virus scan detected for file: {file_info['filename']}")
                        
                        # In virus scanning mode, we might need to handle this differently
                        # Some ICAP clients send the file content in a separate request or expect us to request it
                        
                        # For now, let's try to receive additional data that might contain the file content
                        try:
                            logger.icap_logger.info("Attempting to receive additional file content...")
                            client_socket.settimeout(5.0)  # Short timeout
                            
                            additional_data = b""
                            while len(additional_data) < 100000:  # Reasonable limit
                                chunk = client_socket.recv(8192)
                                if not chunk:
                                    break
                                additional_data += chunk
                                logger.icap_logger.info(f"Received additional chunk: {len(chunk)} bytes (total: {len(additional_data)})")
                                
                                # Look for end of transmission
                                if additional_data.endswith(b'\r\n\r\n'):
                                    break
                                
                                # Safety limit
                                if len(additional_data) > 50000:
                                    logger.icap_logger.warning("Reached safety limit for additional data")
                                    break
                            
                            if additional_data:
                                logger.icap_logger.info(f"Received {len(additional_data)} bytes of additional data")
                                logger.icap_logger.info(f"Additional data preview: {additional_data[:100]}...")
                                
                                # Try to extract file content from additional data
                                # Look for file signatures or content patterns
                                if additional_data.startswith(b'2000'):
                                    # This might be the actual file content with GoAnywhere protocol contamination
                                    logger.icap_logger.warning("Found '2000' prefix in additional data - treating as file content")
                                    
                                    # Remove '2000' and any leading CR/LF
                                    clean_content = additional_data[4:]
                                    while clean_content.startswith(b'\r\n') or clean_content.startswith(b'\n') or clean_content.startswith(b'\r'):
                                        clean_content = clean_content[2:] if clean_content.startswith(b'\r\n') else clean_content[1:]
                                    
                                    logger.icap_logger.info(f"Clean additional content: {len(clean_content)} bytes")
                                    logger.icap_logger.info(f"Clean content starts with: {clean_content[:50]}")
                                    
                                    # Check if this is the complete file (much larger than the direct content)
                                    direct_content_size = len(file_content) if 'file_content' in locals() else 0
                                    if len(clean_content) > direct_content_size * 2:
                                        logger.icap_logger.info(f"Additional data contains complete file ({len(clean_content)} bytes) - saving immediately")
                                        
                                        # Save the complete file from additional data
                                        file_path, record_path = save_file_and_record(file_info, clean_content, client_address, force_save=True)
                                        if file_path and record_path:
                                            logger.icap_logger.info(f"Successfully saved complete file from additional data: {file_info['filename']}")
                                        else:
                                            logger.icap_logger.error(f"Failed to save complete file from additional data: {file_info['filename']}")
                                    else:
                                        logger.icap_logger.info(f"Additional data is not complete, treating as partial")
                                        # Save the partial content from additional data
                                        file_path, record_path = save_file_and_record(file_info, clean_content, client_address, force_save=True)
                                        if file_path and record_path:
                                            logger.icap_logger.info(f"Successfully saved partial file from additional data: {file_info['filename']}")
                                        else:
                                            logger.icap_logger.error(f"Failed to save partial file from additional data: {file_info['filename']}")
                                else:
                                    logger.icap_logger.info("No additional data received or processed")
                            
                        except Exception as e:
                            logger.icap_logger.error(f"Error receiving additional data: {e}")
                    else:
                        logger.icap_logger.warning("Could not extract file information from virus scanning request")
            else:
                logger.icap_logger.warning("No Encapsulated header found in RESPMOD request")
            
            # Send ICAP response
            response = f"""ICAP/1.0 204 No Content\r
Date: {get_current_gmt_time()}\r
Server: FakeICAP/1.0\r
Connection: close\r
ISTag: "FakeICAP-001"\r
\r
\r
""".encode('utf-8')
            client_socket.send(response)
            logger.icap_logger.info("Sent RESPMOD response")
            
        elif 'REQMOD' in data_str:
            # Handle REQMOD request
            logger.icap_logger.info("Processing REQMOD request")
            
            # Parse the Encapsulated header
            encapsulated_header = parse_encapsulated_header(data_str)
            
            if encapsulated_header:
                # Extract the encapsulated content
                file_content = extract_encapsulated_content(data, encapsulated_header)
                
                if file_content:
                    # Extract file information from the encapsulated HTTP headers
                    file_info = extract_file_info_from_icap(data)
                    
                    if file_info and file_info.get('filename'):
                        logger.icap_logger.info(f"Processing file: {file_info['filename']} ({len(file_content)} bytes)")
                        
                        # Save the file as a complete entity body (no ICAP-level
                        # chunk aggregation needed here).
                        file_path, record_path = save_file_and_record(
                            file_info, file_content, client_address, force_save=True
                        )
                        if file_path and record_path:
                            logger.icap_logger.info(f"Successfully saved file: {file_info['filename']}")
                        else:
                            logger.icap_logger.error(f"Failed to save file: {file_info['filename']}")
                    else:
                        logger.icap_logger.warning("Could not extract file information")
                else:
                    logger.icap_logger.warning("Could not extract encapsulated content")
            else:
                logger.icap_logger.warning("No Encapsulated header found in REQMOD request")
            
            # Send ICAP response
            response = f"""ICAP/1.0 204 No Content\r
Date: {get_current_gmt_time()}\r
Server: FakeICAP/1.0\r
Connection: close\r
ISTag: "FakeICAP-001"\r
\r
\r
""".encode('utf-8')
            client_socket.send(response)
            logger.icap_logger.info("Sent REQMOD response")
            
        else:
            # Unknown ICAP request
            logger.icap_logger.warning(f"Unknown ICAP request: {data_str[:100]}...")
            response = f"""ICAP/1.0 400 Bad Request\r
Date: {get_current_gmt_time()}\r
Server: FakeICAP/1.0\r
Connection: close\r
\r
\r
""".encode('utf-8')
            client_socket.send(response)
            logger.icap_logger.info("Sent 400 Bad Request response")
        
    except Exception as e:
        logger.icap_logger.error(f"Error handling ICAP client: {e}")
        try:
            # Send error response
            response = f"""ICAP/1.0 500 Internal Server Error\r
Date: {get_current_gmt_time()}\r
Server: FakeICAP/1.0\r
Connection: close\r
\r
\r
""".encode('utf-8')
            client_socket.send(response)
        except:
            pass
    finally:
        try:
            client_socket.close()
            logger.icap_logger.info("ICAP connection closed")
        except:
            pass

def run_icap_server():
    """Run the ICAP server in a separate thread"""
    global icap_server_running, icap_server_socket, logger
    
    try:
        # Get server configuration from database
        server_host = get_server_host()
        server_port = get_server_port()
        
        # Create socket
        icap_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        icap_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind socket
        icap_server_socket.bind((server_host, server_port))
        
        # Start listening
        icap_server_socket.listen(5)
        icap_server_running = True
        
        logger.app_logger.info(f"=== ICAP SERVER listening on {server_host}:{server_port} ===")
        print(f"=== ICAP SERVER listening on {server_host}:{server_port} ===")
        
        while icap_server_running:
            try:
                # Accept connection
                client_socket, client_address = icap_server_socket.accept()
                
                # Handle client in a new thread
                client_thread = threading.Thread(
                    target=handle_icap_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if icap_server_running:
                    logger.app_logger.error(f"Error accepting ICAP connection: {e}")
                    print(f"Error accepting ICAP connection: {e}")
                break
                
    except Exception as e:
        logger.app_logger.error(f"Error starting ICAP server: {e}")
        print(f"Error starting ICAP server: {e}")
    finally:
        if icap_server_socket:
            icap_server_socket.close()
            logger.app_logger.info("ICAP server socket closed")
            print("ICAP server socket closed")

# Flask Web Application
app = Flask(__name__)
app.secret_key = 'fakeicap-secret-key-change-in-production'

@app.route('/')
def index():
    """Main dashboard"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get recent files
    conn = get_db_connection()
    recent_files = conn.execute('''
        SELECT * FROM processed_files 
        ORDER BY processed_at DESC 
        LIMIT 10
    ''').fetchall()
    conn.close()
    
    return render_template('dashboard.html', recent_files=recent_files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Simple authentication (in production, use proper password hashing)
        if username == 'admin' and password == 'admin':
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/processed_files')
def processed_files():
    """View processed files"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    files = conn.execute('''
        SELECT * FROM processed_files 
        ORDER BY processed_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('processed_files.html', files=files)

@app.route('/download_processed_file/<file_id>')
def download_processed_file(file_id):
    """Download a processed file"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    file_record = conn.execute('SELECT * FROM processed_files WHERE id = ?', (file_id,)).fetchone()
    conn.close()
    
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('processed_files'))
    
    # Search for the file in the date-based directory structure
    file_path = None
    saved_filename = file_record['saved_filename']
    
    # Search in all date directories
    import glob
    search_pattern = os.path.join('saved_files', '**', saved_filename)
    matching_files = glob.glob(search_pattern, recursive=True)
    
    if matching_files:
        file_path = matching_files[0]  # Take the first match
    else:
        flash('File no longer exists on disk', 'error')
        return redirect(url_for('processed_files'))
    
    return send_file(file_path, 
                     download_name=file_record['original_filename'],
                     as_attachment=True)

@app.route('/logs')
def logs():
    """Logs page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    logger_instance = get_logger()
    log_files = logger_instance.get_log_files()
    
    # Get current settings
    conn = get_db_connection()
    settings_data = conn.execute('SELECT key, value FROM settings').fetchall()
    settings_dict = {row['key']: row['value'] for row in settings_data}
    conn.close()
    
    stats = {
        'total_files': len(log_files),
        'total_size_mb': sum(f['size'] for f in log_files) / 1048576,
        'error_logs': len([f for f in log_files if 'error' in f['name']]),
        'security_logs': len([f for f in log_files if 'security' in f['name']]),
        'icap_logs': len([f for f in log_files if 'icap' in f['name']]),
        'web_logs': len([f for f in log_files if 'app' in f['name'] and not any(x in f['name'] for x in ['error', 'security', 'icap', 'web'])])
    }
    
    return render_template('logs.html', log_files=log_files, stats=stats, settings=settings_dict)

def run_transfer_cleanup():
    """Background thread to clean up incomplete transfers"""
    print("Transfer cleanup thread started")
    while True:
        try:
            print(f"Checking {len(ongoing_transfers)} ongoing transfers...")
            cleanup_incomplete_transfers()
            time.sleep(2)  # Check every 2 seconds
        except Exception as e:
            print(f"Error in transfer cleanup: {e}")
            time.sleep(5)

def start_unified():
    """Start both ICAP server and web interface"""
    global logger
    
    try:
        print("=" * 60)
        print("FakeICAP Unified Application Starting")
        print("=" * 60)
        
        # Initialize logger
        logger = get_logger()
        logger.app_logger.info("FakeICAP Unified Application starting up")
        
        # Initialize database
        init_db()
        
        # Load configuration
        server_host = get_server_host()
        server_port = get_server_port()
        logger.app_logger.info(f"Loaded configuration from config.py: host={server_host}, port={server_port}")
        
        # Start ICAP server in background thread
        icap_thread = threading.Thread(target=run_icap_server)
        icap_thread.daemon = True
        icap_thread.start()
        
        # Start transfer cleanup thread
        cleanup_thread = threading.Thread(target=run_transfer_cleanup)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        print(f"Web interface will be available at: http://localhost:5000")
        print(f"ICAP server running on: {server_host}:{server_port}")
        print("Default credentials: admin / admin")
        print("=" * 60)
        
        # Start Flask web interface
        app.run(host='0.0.0.0', port=5000, debug=False)
        
    except Exception as e:
        logger.app_logger.error(f"Error starting unified application: {e}")
        print(f"Error starting unified application: {e}")

def main():
    """Main entry point for the application"""
    start_unified()

if __name__ == '__main__':
    main()
