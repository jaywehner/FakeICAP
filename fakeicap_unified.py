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
import base64
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

try:
    import pgpy
    from pgpy.constants import (
        KeyFlags,
        PubKeyAlgorithm,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )
except ImportError:  # pgpy is optional; if missing, files will be stored plaintext
    pgpy = None
    KeyFlags = None
    PubKeyAlgorithm = None
    HashAlgorithm = None
    SymmetricKeyAlgorithm = None
    CompressionAlgorithm = None

# Add the current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our logger
from logger_config import get_logger

# Global variables
logger = None
icap_server_running = False
icap_server_socket = None
app_start_time = datetime.datetime.utcnow()

# Global dictionary to track ongoing file transfers
ongoing_transfers = {}

# Role-based access control constants
ROLE_ADMIN = 'ADMIN'
ROLE_FULL_ACCESS = 'FULL_ACCESS'
ROLE_LOG_VIEWER = 'LOG_VIEWER'
ROLE_FILE_DOWNLOAD = 'FILE_DOWNLOAD'
ROLE_NO_ACCESS = 'NO_ACCESS'


def user_has_role(*allowed_roles):
    """Check if current user has one of the allowed roles.

    Admin users are always allowed.
    """
    if 'user_id' not in session:
        return False
    if session.get('is_admin'):
        return True
    role = session.get('role') or ROLE_FULL_ACCESS
    return role in allowed_roles

# Timeout for incomplete transfers (in seconds)
TRANSFER_TIMEOUT = 5  # 5 seconds - save quickly since GoAnywhere might not send more chunks

def cleanup_incomplete_transfers():
    """Clean up incomplete transfers that have timed out"""
    current_time = datetime.datetime.now()
    completed_transfers = []
    transfer_count = len(ongoing_transfers)
    if logger is not None:
        logger.app_logger.debug(f"Checking {transfer_count} transfers for timeouts...")
    
    for transfer_key, transfer_data in ongoing_transfers.items():
        # Check if transfer has timed out
        time_since_last_activity = (current_time - transfer_data['last_activity']).total_seconds()
        if logger is not None:
            logger.app_logger.debug(
                f"Transfer {transfer_key}: last activity {time_since_last_activity:.1f} seconds ago"
            )
        
        if time_since_last_activity > TRANSFER_TIMEOUT:
            if logger is not None:
                logger.app_logger.info(f"Transfer timeout for {transfer_key} - saving incomplete content")
            
            # Save the incomplete content
            try:
                file_content = bytes(transfer_data['content'])
                file_info = transfer_data['file_info']
                client_address = transfer_data.get('client_address')
                if logger is not None:
                    logger.app_logger.info(
                        f"Saving incomplete transfer for {transfer_key}: {len(file_content)} bytes"
                    )
                # Let save_file_and_record handle encryption so logic is centralized
                file_path, record_path = save_file_and_record(
                    file_info, file_content, client_address, force_save=True
                )
                if logger is not None:
                    if file_path and record_path:
                        logger.app_logger.info(
                            f"Successfully saved incomplete transfer: {file_info.get('filename', 'unknown')}"
                        )
                    else:
                        logger.app_logger.warning(
                            f"Failed to save incomplete transfer: {file_info.get('filename', 'unknown')}"
                        )
                
                completed_transfers.append(transfer_key)
            except Exception as e:
                if logger is not None:
                    logger.app_logger.error(f"Error saving incomplete transfer {transfer_key}: {e}")
                completed_transfers.append(transfer_key)
    
    # Remove completed transfers
    for transfer_key in completed_transfers:
        del ongoing_transfers[transfer_key]
    
    if completed_transfers and logger is not None:
        logger.app_logger.info(f"Cleaned up {len(completed_transfers)} timed out transfers")

def get_server_host():
    """Get ICAP server host from database settings"""
    try:
        conn = get_db_connection()
        if conn is None:
            return '0.0.0.0'
        row = conn.execute(
            'SELECT value FROM settings WHERE key = ?',
            ('icap_host',),
        ).fetchone()
        conn.close()

        host = row['value'] if row else '0.0.0.0'
        # Treat placeholder values as wildcard
        if host == 'YOUR_SERVER_IP':
            return '0.0.0.0'
        return host
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f"Error getting server host from database: {e}")
        return '0.0.0.0'

def get_server_port():
    """Get ICAP server port from database settings"""
    try:
        conn = get_db_connection()
        if conn is None:
            return 1344
        row = conn.execute(
            'SELECT value FROM settings WHERE key = ?',
            ('icap_port',),
        ).fetchone()
        conn.close()

        if row and row['value']:
            try:
                return int(row['value'])
            except ValueError:
                return 1344
        return 1344
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f"Error getting server port from database: {e}")
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
        
        # Calculate file hash on the original plaintext content
        file_hash = hashlib.sha256(file_content).hexdigest()
        print(f"File hash: {file_hash}")

        # Look up the currently active PGP key (if any) so we can record the
        # fingerprint used for this file.
        pgp_info = get_pgp_settings()
        active_fingerprint = pgp_info.get('fingerprint') if isinstance(pgp_info, dict) else None

        # Optionally encrypt the file content at rest using the configured
        # PGP public key. If encryption fails for any reason, fall back to
        # saving the plaintext to avoid data loss.
        encrypted_content = file_content
        try:
            encrypted_content = encrypt_file_content(file_content)
        except Exception as enc_err:
            if logger is not None:
                logger.app_logger.error(
                    f"PGP encryption failed, saving plaintext instead: {enc_err}"
                )

        # If encryption actually changed the bytes, record the fingerprint
        # of the key that was in use at the time.
        used_fingerprint = None
        if active_fingerprint and encrypted_content != file_content:
            used_fingerprint = active_fingerprint
        
        # Save the (possibly encrypted) file
        with open(file_path, 'wb') as f:
            f.write(encrypted_content)
        print(f"File saved successfully: {file_path} ({len(encrypted_content)} bytes)")
        
        # Create and save record file
        record_content = f"""File Record
==========
GUID: {shared_guid}
Original Filename: {original_filename}
Saved Filename: {file_filename}
File Size: {len(file_content)} bytes
File Hash (SHA256): {file_hash}
PGP Fingerprint: {used_fingerprint or 'None'}
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
            (id, original_filename, saved_filename, file_size, file_hash, client_ip, user_agent, processed_at, date_processed, pgp_fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            shared_guid,
            original_filename,
            file_filename,
            len(file_content),
            file_hash,
            client_address[0] if client_address else None,
            user_agent,
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            datetime.datetime.now().strftime('%Y-%m-%d'),
            used_fingerprint,
        ))
        
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


def get_db_key_cipher():
    """Return a Fernet cipher for encrypting sensitive DB fields, or None.

    The cipher key is derived from the FAKEICAP_KEY_SECRET environment
    variable. If this variable is not set, we fall back to a secret stored
    in the database settings table under the key 'db_encryption_secret'.
    If no secret is available or something goes wrong, the function returns
    None and callers should fall back to storing plaintext.
    """
    secret = os.environ.get('FAKEICAP_KEY_SECRET')
    if not secret:
        # Fallback: look for a secret stored in the settings table
        conn = None
        try:
            conn = get_db_connection()
            if conn is not None:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key = 'db_encryption_secret'"
                ).fetchone()
                if row:
                    # sqlite3.Row supports both index and key access
                    secret = row[0]
        except Exception as e:
            if logger is not None:
                logger.app_logger.error(f"Error reading db_encryption_secret from DB: {e}")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    if not secret:
        return None
    try:
        key_bytes = hashlib.sha256(secret.encode('utf-8')).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        return Fernet(fernet_key)
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f"Error initializing DB key cipher: {e}")
        return None


def encrypt_for_db(plaintext):
    """Encrypt a string for storage in the database.

    If DB encryption is not configured, the original plaintext is returned.
    """
    if plaintext is None:
        return None
    cipher = get_db_key_cipher()
    if cipher is None:
        return plaintext
    token = cipher.encrypt(plaintext.encode('utf-8'))
    return token.decode('ascii')


def decrypt_from_db(ciphertext):
    """Decrypt a string previously stored in the database.

    If DB encryption is not configured or decryption fails, the original
    ciphertext is returned unchanged.
    """
    if ciphertext is None:
        return None
    cipher = get_db_key_cipher()
    if cipher is None:
        return ciphertext
    try:
        data = cipher.decrypt(ciphertext.encode('ascii'))
        return data.decode('utf-8')
    except Exception:
        return ciphertext


def get_pgp_settings():
    """Return active PGP key material from the database.

    This first looks in the pgp_keys table for the current active key.
    If none is found, it falls back to the legacy settings-based storage
    (pgp_public_key/pgp_private_key/pgp_private_passphrase).
    """
    conn = get_db_connection()
    if conn is None:
        return {"public": None, "private": None, "passphrase": None, "fingerprint": None}

    try:
        cursor = conn.cursor()
        # Preferred: managed keys in pgp_keys
        try:
            row = cursor.execute(
                "SELECT fingerprint, public_key, private_key "
                "FROM pgp_keys WHERE is_active = 1 ORDER BY id DESC LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError:
            row = None

        if row:
            public_key = decrypt_from_db(row["public_key"])
            private_key = decrypt_from_db(row["private_key"])
            return {
                "public": public_key,
                "private": private_key,
                "passphrase": None,
                "fingerprint": row["fingerprint"],
            }

        # Fallback: legacy storage in settings table
        rows = cursor.execute("SELECT key, value FROM settings").fetchall()
        values = {r["key"]: r["value"] for r in rows}
        return {
            "public": values.get("pgp_public_key") or None,
            "private": values.get("pgp_private_key") or None,
            "passphrase": values.get("pgp_private_passphrase") or None,
            "fingerprint": None,
        }
    finally:
        conn.close()


def get_pgp_key_by_fingerprint(fingerprint):
    """Return PGP key material for a specific fingerprint, or fall back to active settings."""
    if not fingerprint:
        return get_pgp_settings()

    conn = get_db_connection()
    if conn is None:
        return get_pgp_settings()

    try:
        row = conn.execute(
            "SELECT fingerprint, public_key, private_key FROM pgp_keys WHERE fingerprint = ? LIMIT 1",
            (fingerprint,),
        ).fetchone()
        if row:
            public_key = decrypt_from_db(row["public_key"])
            private_key = decrypt_from_db(row["private_key"])
            return {
                "public": public_key,
                "private": private_key,
                "passphrase": None,
                "fingerprint": row["fingerprint"],
            }
        return get_pgp_settings()
    finally:
        conn.close()


def encrypt_file_content(plaintext: bytes) -> bytes:
    """Encrypt file content with the configured PGP public key.

    If no public key is configured or pgpy is unavailable, the plaintext is
    returned unchanged.
    """
    if not plaintext:
        return plaintext

    if pgpy is None:
        if logger is not None:
            logger.app_logger.warning("PGP encryption requested but pgpy library is not available; storing plaintext.")
        return plaintext

    settings = get_pgp_settings()
    public_key_data = settings["public"]
    if not public_key_data:
        if logger is not None:
            logger.app_logger.info("PGP public key not configured; storing plaintext.")
        return plaintext

    try:
        if logger is not None:
            logger.app_logger.info("Encrypting file content with configured PGP public key.")
        pub_key, _ = pgpy.PGPKey.from_blob(public_key_data)
        message = pgpy.PGPMessage.new(plaintext, file=True)

        # Let pgpy select the appropriate key/subkey for encryption.
        encrypted = pub_key.encrypt(message)

        # Store as ASCII-armored ciphertext on disk
        return str(encrypted).encode('utf-8')
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f"Error during PGP encryption; storing plaintext instead: {e}")
        # Fail open: return plaintext so we do not lose the file
        return plaintext


def decrypt_file_content(ciphertext: bytes, fingerprint=None) -> bytes:
    """Decrypt file content with the configured PGP private key.

    If decryption fails or keys are not configured/usable, the original
    ciphertext is returned and the caller may decide how to handle it.
    """
    if not ciphertext:
        return ciphertext

    if pgpy is None:
        return ciphertext

    if fingerprint:
        settings = get_pgp_key_by_fingerprint(fingerprint)
    else:
        settings = get_pgp_settings()
    private_key_data = settings["private"]
    passphrase = settings["passphrase"]
    if not private_key_data:
        return ciphertext

    try:
        priv_key, _ = pgpy.PGPKey.from_blob(private_key_data)
        message = pgpy.PGPMessage.from_blob(ciphertext)

        if priv_key.is_protected and passphrase:
            with priv_key.unlock(passphrase):
                decrypted = priv_key.decrypt(message)
        else:
            decrypted = priv_key.decrypt(message)

        # PGPMessage.message returns bytes for binary payloads
        return decrypted.message
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f"Error during PGP decryption: {e}")
        # Fail closed for safety: propagate ciphertext so the caller can
        # decide whether to deny the download or return the raw data.
        return ciphertext

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
                date_processed TEXT NOT NULL,
                pgp_fingerprint TEXT
            )
        ''')

        # Ensure pgp_fingerprint column exists for older databases
        try:
            cursor.execute("ALTER TABLE processed_files ADD COLUMN pgp_fingerprint TEXT")
        except sqlite3.OperationalError:
            # Column already exists; safe to ignore
            pass
        
        # Create settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')

        # Create pgp_keys table to hold internally managed PGP key pairs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pgp_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
        ''')

        # Insert default settings
        cursor.execute('''
            INSERT OR IGNORE INTO settings (key, value) VALUES 
            ('icap_host', '10.10.0.5'),
            ('icap_port', '1344'),
            ('web_host', 'localhost'),
            ('web_port', '5000'),
            ('max_file_size', '52428800'),
            ('file_timeout', '15'),
            ('theme', 'light'),
            ('accent_color', 'orange'),
            ('log_max_bytes', '5242880'),
            ('log_backup_count', '10'),
            ('file_history_days', '30'),
            ('password_min_length', '6'),
            ('password_min_uppercase', '0'),
            ('password_min_lowercase', '0'),
            ('password_min_digits', '0'),
            ('password_min_special', '0'),
            ('password_allowed_specials', '!@#$%^&*()-_=+[]{};:,.<>/?'),
            ('registration_enabled', '0')
        ''')

        # Create users table for web interface authentication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        ''')

        # Ensure role column exists for role-based access control
        try:
            cursor.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'FULL_ACCESS'"
            )
        except sqlite3.OperationalError:
            # Column already exists or table not yet created; safe to ignore
            pass

        # Backfill missing roles for existing users (non-admins default to FULL_ACCESS)
        try:
            cursor.execute(
                "UPDATE users SET role = 'FULL_ACCESS' WHERE (role IS NULL OR role = '') AND id != 1"
            )
        except sqlite3.OperationalError:
            # If role column didn't exist yet, this will be a no-op
            pass

        # Ensure default admin user exists (admin / admin)
        admin_password_hash = generate_password_hash('admin')
        cursor.execute('''
            INSERT OR IGNORE INTO users (id, username, password_hash, is_admin, must_change_password, created_at)
            VALUES (1, 'admin', ?, 1, 1, ?)
        ''', (admin_password_hash, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

        cursor.execute('''
            UPDATE users
            SET must_change_password = 1
            WHERE id = 1 AND (last_login IS NULL OR last_login = '')
        ''')

        # Ensure default admin has ADMIN role
        cursor.execute(
            "UPDATE users SET role = 'ADMIN', is_admin = 1 WHERE id = 1"
        )

        conn.commit()
        conn.close()
        print("Database initialized successfully")
        
    except Exception as e:
        print(f"Error initializing database: {e}")

def get_server_status():
    try:
        uptime = "Unknown"
        uptime_seconds = 0
        if app_start_time:
            delta = datetime.datetime.utcnow() - app_start_time
            uptime_seconds = int(delta.total_seconds())
            days = uptime_seconds // 86400
            rem = uptime_seconds % 86400
            hours, rem = divmod(rem, 3600)
            minutes, seconds = divmod(rem, 60)
            if days > 0:
                uptime = f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                uptime = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        files_processed = 0
        last_file = "None"
        active_transfers = len(ongoing_transfers)

        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            today = datetime.datetime.now().strftime('%Y-%m-%d')
            cursor.execute("SELECT COUNT(*) FROM processed_files WHERE date_processed = ?", (today,))
            row = cursor.fetchone()
            if row:
                files_processed = row[0]

            cursor.execute("SELECT original_filename FROM processed_files ORDER BY processed_at DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                if isinstance(row, sqlite3.Row):
                    last_file = row["original_filename"]
                else:
                    last_file = row[0]

            conn.close()

        # Build active connections list from ongoing_transfers
        connections = []
        now = datetime.datetime.now()
        for key, data in ongoing_transfers.items():
            client = None
            client_addr = data.get('client_address')
            if client_addr and isinstance(client_addr, (list, tuple)) and len(client_addr) > 0:
                client = client_addr[0]
            file_info = data.get('file_info') or {}
            filename = file_info.get('filename', 'unknown')
            bytes_received = len(data.get('content') or [])
            chunks = data.get('chunks_received', 1)
            last_activity = data.get('last_activity') or now
            age_seconds = int((now - last_activity).total_seconds())
            connections.append({
                'key': key,
                'client': client or 'Unknown',
                'filename': filename or 'unknown',
                'bytes': bytes_received,
                'chunks': chunks,
                'age_seconds': age_seconds,
            })

        return {
            "uptime": uptime,
            "uptime_seconds": uptime_seconds,
            "files_processed": files_processed,
            "last_file": last_file,
            "active_transfers": active_transfers,
            "connections": connections,
        }
    except Exception as e:
        print(f"Error getting server status: {e}")
        return {
            "uptime": "Unknown",
            "uptime_seconds": 0,
            "files_processed": 0,
            "last_file": "None",
            "active_transfers": 0,
            "connections": [],
        }

def get_password_policy():
    """Load password complexity policy from settings with sensible defaults."""
    conn = get_db_connection()
    policy = {
        'min_length': 6,
        'min_uppercase': 0,
        'min_lowercase': 0,
        'min_digits': 0,
        'min_special': 0,
        'allowed_specials': '!@#$%^&*()-_=+[]{};:,.<>/?',
    }
    if conn:
        rows = conn.execute('SELECT key, value FROM settings').fetchall()
        conn.close()
        values = {row['key']: row['value'] for row in rows}
        try:
            policy['min_length'] = int(values.get('password_min_length', policy['min_length']) or 0)
            policy['min_uppercase'] = int(values.get('password_min_uppercase', policy['min_uppercase']) or 0)
            policy['min_lowercase'] = int(values.get('password_min_lowercase', policy['min_lowercase']) or 0)
            policy['min_digits'] = int(values.get('password_min_digits', policy['min_digits']) or 0)
            policy['min_special'] = int(values.get('password_min_special', policy['min_special']) or 0)
        except ValueError:
            # Fall back to defaults if parsing fails
            pass
        policy['allowed_specials'] = values.get('password_allowed_specials', policy['allowed_specials'])
    return policy

def validate_password_complexity(password):
    """Validate password against the configured complexity policy.

    Returns (ok, message). If ok is False, message describes *all* violated
    rules so the user can correct them in one attempt.
    """
    if not password:
        return False, 'Password cannot be empty.'

    policy = get_password_policy()
    length = len(password)
    upper = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    digits = sum(1 for c in password if c.isdigit())
    specials = 0
    allowed = policy['allowed_specials'] or ''
    if allowed:
        specials = sum(1 for c in password if c in allowed)

    issues = []

    # Length requirement (0 disables the check)
    if policy['min_length'] > 0 and length < policy['min_length']:
        issues.append(f'Password must be at least {policy["min_length"]} characters long.')

    if policy['min_uppercase'] > 0 and upper < policy['min_uppercase']:
        issues.append(f'Password must contain at least {policy["min_uppercase"]} uppercase letter(s).')

    if policy['min_lowercase'] > 0 and lower < policy['min_lowercase']:
        issues.append(f'Password must contain at least {policy["min_lowercase"]} lowercase letter(s).')

    if policy['min_digits'] > 0 and digits < policy['min_digits']:
        issues.append(f'Password must contain at least {policy["min_digits"]} digit(s).')

    if policy['min_special'] > 0:
        if not allowed:
            issues.append('Password policy requires special characters but no allowed set is configured.')
        elif specials < policy['min_special']:
            issues.append(f'Password must contain at least {policy["min_special"]} special character(s).')

    if issues:
        # Combine all issues into a single message for display
        return False, 'Password does not meet the following requirements: ' + ' '.join(issues)

    return True, ''

def get_available_ipv4_addresses():
    """Return a list of IPv4 addresses for the local machine.

    Used to populate the Server Host dropdown on the dashboard.
    """
    addresses = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            ip = info[4][0]
            addresses.add(ip)
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f"Error enumerating IPv4 addresses: {e}")

    # Always include common options
    addresses.add('127.0.0.1')
    addresses.add('0.0.0.0')

    # Sort so 0.0.0.0 and 127.0.0.1 appear first
    def sort_key(ip):
        if ip == '0.0.0.0':
            return (0, ip)
        if ip == '127.0.0.1':
            return (1, ip)
        return (2, ip)

    return sorted(addresses, key=sort_key)

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
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'supersecretkey')

@app.context_processor
def inject_global_settings():
    """Inject settings (including theme and accent color) into all templates.

    This allows base.html to apply the configured global theme/accent for everyone.
    """
    settings = {}
    try:
        conn = get_db_connection()
        rows = conn.execute('SELECT key, value FROM settings').fetchall()
        settings = {row['key']: row['value'] for row in rows}
    except Exception:
        # If the settings table doesn't exist yet (e.g., during first run), fall back to defaults.
        settings = {}
    finally:
        try:
            conn.close()
        except Exception:
            pass

    ui_theme = settings.get('theme', 'light')
    ui_accent_color = settings.get('accent_color', 'orange')
    return dict(settings=settings, ui_theme=ui_theme, ui_accent_color=ui_accent_color)

@app.before_request
def enforce_mandatory_password_change():
    """Force users flagged with must_change_password to update their password before using the app."""
    if 'user_id' not in session:
        return

    if not session.get('must_change_password'):
        return

    # Allow access only to change_password, login, logout, and static resources
    endpoint = request.endpoint or ''
    allowed = {'change_password', 'login', 'logout', 'static'}
    if endpoint in allowed or endpoint.startswith('static'):
        return

    flash('You must change your password before continuing.', 'warning')
    return redirect(url_for('change_password'))

@app.route('/')
def index():
    """Main dashboard"""
    # If not authenticated, send user to login page
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Users with NO_ACCESS role should not see the dashboard until approved
    if not user_has_role(ROLE_FULL_ACCESS, ROLE_LOG_VIEWER, ROLE_FILE_DOWNLOAD):
        return redirect(url_for('no_access'))

    conn = get_db_connection()
    recent_files = conn.execute('''
        SELECT * FROM processed_files 
        ORDER BY processed_at DESC 
        LIMIT 10
    ''').fetchall()

    settings_rows = conn.execute('SELECT key, value FROM settings').fetchall()
    settings = {row['key']: row['value'] for row in settings_rows}

    # Provide friendly aliases expected by the templates
    settings.setdefault('server_host', settings.get('icap_host', get_server_host()))
    settings.setdefault('server_port', settings.get('icap_port', str(get_server_port())))

    conn.close()

    server_status = get_server_status()
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    server_hosts = get_available_ipv4_addresses()

    return render_template(
        'dashboard.html',
        recent_files=recent_files,
        server_status=server_status,
        settings=settings,
        current_time=current_time,
        server_hosts=server_hosts,
    )

@app.route('/dashboard')
def dashboard():
    """Alias route for the main dashboard"""
    # Reuse the existing index logic (which already handles auth)
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # If already logged in, go straight to dashboard
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Look up user in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            # Successful login
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            session['must_change_password'] = bool(user['must_change_password'])
            # Track role for non-admin access control
            user_role = user['role'] if 'role' in user.keys() else ROLE_FULL_ACCESS
            if session['is_admin']:
                user_role = ROLE_ADMIN
            session['role'] = user_role

            # Update last_login
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE users SET last_login = ? WHERE id = ?',
                    (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id'])
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

            # If user must change password, send them there first
            if session.get('must_change_password'):
                return redirect(url_for('change_password'))

            # Users with NO_ACCESS role cannot use the app until approved
            if not session.get('is_admin') and session.get('role') == ROLE_NO_ACCESS:
                flash('Your account is pending approval. Please contact an administrator.', 'warning')
                return redirect(url_for('no_access'))

            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'error')

    # Load settings so the login page can conditionally show default credentials hint
    conn = get_db_connection()
    settings_data = conn.execute('SELECT key, value FROM settings').fetchall() if conn else []
    if conn:
        conn.close()
    settings = {row['key']: row['value'] for row in settings_data} if settings_data else {}
    
    return render_template('login.html', settings=settings)

@app.route('/logout')
def logout():
    """Logout"""
    # Clear all auth-related session keys
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('is_admin', None)
    session.pop('must_change_password', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/processed_files')
def processed_files():
    """View processed files"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Require appropriate role: full access or file-download
    if not user_has_role(ROLE_FULL_ACCESS, ROLE_FILE_DOWNLOAD):
        flash('You do not have permission to view processed files.', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()

    # Load settings for history window
    settings_rows = conn.execute('SELECT key, value FROM settings').fetchall()
    settings = {row['key']: row['value'] for row in settings_rows}
    history_days = int(settings.get('file_history_days', '30') or '30')

    # Filters
    # Default the date filter to *today* when no explicit date is provided,
    # so the page always starts on today's files.
    today_str = datetime.date.today().strftime('%Y-%m-%d')
    raw_date = request.args.get('date')
    if raw_date is None or raw_date == '':
        selected_date = today_str
    else:
        selected_date = raw_date
    search_term = (request.args.get('search') or '').strip()

    # Build query with optional filters
    query = 'SELECT * FROM processed_files WHERE 1=1'
    params = []
    if selected_date:
        query += ' AND date_processed = ?'
        params.append(selected_date)
    if search_term:
        query += ' AND original_filename LIKE ?'
        params.append(f"%{search_term}%")
    query += ' ORDER BY processed_at DESC'

    files = conn.execute(query, params).fetchall()

    # Date options with counts
    dates = conn.execute('''
        SELECT date_processed, COUNT(*) AS file_count
        FROM processed_files
        GROUP BY date_processed
        ORDER BY date_processed DESC
    ''').fetchall()

    conn.close()

    # Render the processed files list; decryption happens only in
    # download_processed_file when an individual file is downloaded.
    return render_template(
        'processed_files.html',
        files=files,
        history_days=history_days,
        dates=dates,
        selected_date=selected_date,
        search_term=search_term,
    )

@app.route('/file_details/<file_id>')
def file_details(file_id):
    """Return JSON details for a processed file (used by modal)."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if not user_has_role(ROLE_FULL_ACCESS, ROLE_FILE_DOWNLOAD):
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db_connection()
    file_record = conn.execute(
        'SELECT * FROM processed_files WHERE id = ?', (file_id,)
    ).fetchone()
    conn.close()

    if not file_record:
        return jsonify({'error': 'File not found'}), 404

    # Locate file on disk (same logic as download_processed_file)
    import glob
    saved_filename = file_record['saved_filename']
    search_pattern = os.path.join('saved_files', '**', saved_filename)
    matching_files = glob.glob(search_pattern, recursive=True)
    directory = None
    full_path = None
    if matching_files:
        full_path = os.path.abspath(matching_files[0])
        directory = os.path.dirname(full_path)

    details = {
        'Record ID': file_record['id'],
        'Filename': file_record['original_filename'],
        'Corresponding File': file_record['saved_filename'],
        'File Size': f"{file_record['file_size']} bytes",
        'File Hash': file_record['file_hash'],
        'Client IP': file_record['client_ip'] or 'Unknown',
        'User Agent': file_record['user_agent'] or 'Unknown',
        'Timestamp': file_record['processed_at'],
        'Method': 'ICAP',
        'Status': 'Saved',
    }

    if full_path:
        details['Directory'] = directory
        details['Full File Path'] = full_path

    return jsonify(details)

@app.route('/download_processed_file/<file_id>')
def download_processed_file(file_id):
    """Download a processed file"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not user_has_role(ROLE_FULL_ACCESS, ROLE_FILE_DOWNLOAD):
        flash('You do not have permission to download files.', 'error')
        return redirect(url_for('index'))
    
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

    # Read file content and decrypt if it was stored encrypted with a PGP key
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
    except OSError:
        flash('Unable to read file from disk', 'error')
        return redirect(url_for('processed_files'))

    fingerprint = file_record['pgp_fingerprint'] if 'pgp_fingerprint' in file_record.keys() else None
    decrypted_data = decrypt_file_content(raw_data, fingerprint=fingerprint)

    return send_file(
        BytesIO(decrypted_data),
        download_name=file_record['original_filename'],
        as_attachment=True,
    )


@app.route('/generate_pgp_key', methods=['POST'])
def generate_pgp_key():
    """Generate a new internal PGP key pair and mark it active (admin only)."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to manage PGP keys.', 'error')
        return redirect(url_for('settings_page'))

    if pgpy is None or PubKeyAlgorithm is None or KeyFlags is None:
        flash('PGP support is not available on this server.', 'error')
        return redirect(url_for('settings_page'))

    try:
        # Generate a new RSA key suitable for encryption
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        uid = pgpy.PGPUID.new('FakeICAP Storage Key')

        key.add_uid(
            uid,
            usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512],
            ciphers=[
                SymmetricKeyAlgorithm.AES256,
                SymmetricKeyAlgorithm.AES192,
                SymmetricKeyAlgorithm.AES128,
            ],
            compression=[
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.BZ2,
                CompressionAlgorithm.ZIP,
                CompressionAlgorithm.Uncompressed,
            ],
        )

        fingerprint = key.fingerprint
        public_key = str(key.pubkey)
        private_key = str(key)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Mark all existing keys as inactive
            cursor.execute('UPDATE pgp_keys SET is_active = 0')
        except sqlite3.OperationalError:
            # Table might not exist yet; it will be created by init_db
            pass

        cursor.execute(
            '''INSERT INTO pgp_keys (fingerprint, public_key, private_key, is_active, created_at)
               VALUES (?, ?, ?, 1, ?)''',
            (
                fingerprint,
                encrypt_for_db(public_key),
                encrypt_for_db(private_key),
                datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ),
        )
        conn.commit()
        conn.close()

        if logger is not None:
            logger.app_logger.info(f'Generated new PGP key with fingerprint {fingerprint}')
        flash('New PGP encryption key generated and activated.', 'success')
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f'Failed to generate PGP key: {e}')
        flash('Failed to generate PGP key. See logs for details.', 'error')

    return redirect(url_for('settings_page'))


@app.route('/init_db_encryption_secret', methods=['POST'])
def init_db_encryption_secret():
    """Initialize a database-stored encryption secret for PGP key storage.

    This is used only when the FAKEICAP_KEY_SECRET environment variable is
    not set. Admin-only; does nothing if a secret already exists.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to manage encryption settings.', 'error')
        return redirect(url_for('settings_page'))

    # If an environment variable is present, we do not need or use the DB
    # secret and should avoid creating a redundant value.
    if os.environ.get('FAKEICAP_KEY_SECRET'):
        flash('FAKEICAP_KEY_SECRET is already set in the server environment; '
              'database-stored secret is not used.', 'warning')
        return redirect(url_for('settings_page'))

    conn = get_db_connection()
    if conn is None:
        flash('Unable to access database to initialize encryption secret.', 'error')
        return redirect(url_for('settings_page'))

    try:
        cursor = conn.cursor()
        row = cursor.execute(
            "SELECT value FROM settings WHERE key = 'db_encryption_secret'"
        ).fetchone()
        if row:
            flash('A database encryption secret is already configured.', 'info')
            return redirect(url_for('settings_page'))

        # Generate a new random secret. This value is never logged and is used
        # only to derive the Fernet key for encrypting sensitive DB fields.
        secret_bytes = os.urandom(32)
        secret = base64.urlsafe_b64encode(secret_bytes).decode('ascii')

        cursor.execute(
            "INSERT INTO settings (key, value) VALUES ('db_encryption_secret', ?)",
            (secret,),
        )
        conn.commit()
        flash('Database encryption secret initialized successfully.', 'success')
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f'Failed to initialize DB encryption secret: {e}')
        flash('Failed to initialize database encryption secret. See logs for details.', 'error')
    finally:
        conn.close()

    return redirect(url_for('settings_page'))


@app.route('/restart_icap', methods=['POST'])
def restart_icap():
    """Restart the ICAP server in the background (admin only)."""
    global icap_server_running, icap_server_socket

    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if not session.get('is_admin'):
        return jsonify({'error': 'Forbidden'}), 403

    try:
        # Signal current server loop to stop
        icap_server_running = False
        if icap_server_socket:
            try:
                icap_server_socket.close()
            except Exception:
                pass
            icap_server_socket = None

        # Start a fresh ICAP server thread with current configuration
        icap_thread = threading.Thread(target=run_icap_server)
        icap_thread.daemon = True
        icap_thread.start()

        if logger is not None:
            logger.app_logger.info('ICAP server restart requested via web UI.')

        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        if logger is not None:
            logger.app_logger.error(f'Failed to restart ICAP server: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/logs')
def logs():
    """Logs page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Allow Admin, Full Access, and Log Viewer roles
    if not user_has_role(ROLE_FULL_ACCESS, ROLE_LOG_VIEWER):
        flash('You do not have permission to view logs.', 'error')
        return redirect(url_for('index'))
    
    logger_instance = get_logger()
    log_files = logger_instance.get_log_files()

    # Get current settings for display in the Log Configuration section
    conn = get_db_connection()
    settings_data = conn.execute('SELECT key, value FROM settings').fetchall()
    settings_dict = {row['key']: row['value'] for row in settings_data}
    conn.close()

    # Basic statistics about available log files
    stats = {
        'total_files': len(log_files),
        'total_size_mb': sum(f['size'] for f in log_files) / 1048576 if log_files else 0,
        'error_logs': len([f for f in log_files if 'error' in f['name']]),
        'security_logs': len([f for f in log_files if 'security' in f['name']]),
        'icap_logs': len([f for f in log_files if 'icap' in f['name']]),
        'web_logs': len([
            f for f in log_files
            if 'app' in f['name'] and not any(x in f['name'] for x in ['error', 'security', 'icap', 'web'])
        ]),
    }

    return render_template('logs.html', log_files=log_files, stats=stats, settings=settings_dict)

@app.route('/logs/view/<path:filename>')
def view_log(filename):
    """View a specific log file"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    logger_instance = get_logger()
    log_content = logger_instance.get_log_content(filename, lines=200)
    if log_content is None:
        flash('Log file not found', 'error')
        return redirect(url_for('logs'))

    # Basic statistics
    total_lines = len(log_content)
    error_count = sum(1 for line in log_content if 'ERROR' in line)
    warning_count = sum(1 for line in log_content if 'WARNING' in line)
    info_count = sum(1 for line in log_content if 'INFO' in line)

    stats = {
        'total_lines': total_lines,
        'error_count': error_count,
        'warning_count': warning_count,
        'info_count': info_count,
    }

    return render_template('log_view.html', filename=filename, log_content=log_content, stats=stats)

@app.route('/download_log/<path:filename>')
def download_log(filename):
    """Download a log file"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_path = os.path.join('logs', filename)
    if not os.path.isfile(file_path):
        flash('Log file not found', 'error')
        return redirect(url_for('logs'))

    return send_file(file_path, as_attachment=True)

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    """Clear all log files (admin only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to clear logs.', 'error')
        return redirect(url_for('logs'))

    logger_instance = get_logger()
    success = logger_instance.clear_logs()
    if success:
        flash('Log files cleared successfully.', 'success')
    else:
        flash('Failed to clear log files.', 'error')
    return redirect(url_for('logs'))

@app.route('/update_settings', methods=['POST'])
def update_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Only administrators can change global settings
    if not session.get('is_admin'):
        flash('Admin privileges are required to update settings.', 'error')
        return redirect(url_for('index'))

    keys = [
        'server_host',
        'server_port',
        'max_file_size',
        'file_timeout',
        'theme',
        'accent_color',
        'log_max_bytes',
        'log_backup_count',
        'file_history_days',
        'password_min_length',
        'password_min_uppercase',
        'password_min_lowercase',
        'password_min_digits',
        'password_min_special',
        'password_allowed_specials',
        'registration_enabled',
        'pgp_public_key',
        'pgp_private_key',
        'pgp_private_passphrase',
    ]

    conn = get_db_connection()
    cursor = conn.cursor()

    # Load current values so we can preserve sensitive fields when left blank
    existing_rows = cursor.execute('SELECT key, value FROM settings').fetchall()
    existing_values = {row['key']: row['value'] for row in existing_rows}

    for key in keys:
        # registration_enabled is a checkbox that only appears on the Users page.
        # Only update it when present in the submitted form so other settings
        # forms (e.g. Logs or Dashboard) don't inadvertently reset it.
        if key == 'registration_enabled':
            if 'registration_enabled' not in request.form:
                continue
            value = '1' if request.form.get('registration_enabled') == 'on' else '0'
        else:
            value = request.form.get(key)

        # For PGP key material and passphrase, treat an empty string as
        # "leave unchanged" so we don't wipe values every time Settings is saved.
        if key in {'pgp_public_key', 'pgp_private_key', 'pgp_private_passphrase'}:
            if value is None:
                # Field not present in this form; skip
                continue
            if value.strip() == '':
                # Keep existing value if one exists
                if key in existing_values:
                    continue

        if value is not None:
            db_key = key
            if key == 'server_host':
                db_key = 'icap_host'
            elif key == 'server_port':
                db_key = 'icap_port'
            cursor.execute(
                'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                (db_key, str(value)),
            )

    conn.commit()
    conn.close()

    flash('Settings updated successfully', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User self-registration.

    Controlled by the 'registration_enabled' setting in the settings table.
    When disabled, users are redirected back to login with a friendly message.
    When enabled, a standard registration flow is used with password policy
    enforcement.
    """

    # Read registration flag from settings
    conn = get_db_connection()
    settings_values = {}
    if conn:
        rows = conn.execute('SELECT key, value FROM settings').fetchall()
        conn.close()
        settings_values = {row['key']: row['value'] for row in rows}

    registration_enabled = settings_values.get('registration_enabled', '0') == '1'

    if not registration_enabled:
        # Registration is currently disabled
        flash('User self-registration is not enabled at this time.', 'warning')
        return redirect(url_for('login'))

    # Registration is enabled
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        # Enforce password complexity policy
        ok, message = validate_password_complexity(password)
        if not ok:
            flash(message, 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            password_hash = generate_password_hash(password)
            # Self-registered users always start as NO_ACCESS until approved
            cursor.execute(
                'INSERT INTO users (username, password_hash, is_admin, must_change_password, created_at, role) VALUES (?, ?, ?, ?, ?, ?)',
                (username, password_hash, 0, 0, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ROLE_NO_ACCESS),
            )
            conn.commit()
            flash('Account created successfully and is pending approval by an administrator.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/settings')
def settings_page():
    """Application settings page (admin only).

    Provides ICAP server settings and UI preferences that were previously on the
    dashboard.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to view settings.', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    settings_rows = conn.execute('SELECT key, value FROM settings').fetchall()
    settings = {row['key']: row['value'] for row in settings_rows}

    # Provide friendly aliases for template usage
    settings.setdefault('server_host', settings.get('icap_host', get_server_host()))
    settings.setdefault('server_port', settings.get('icap_port', str(get_server_port())))

    # PGP key status for display
    pgp_status = {
        'active_fingerprint': None,
        'created_at': None,
        'total_keys': 0,
        # Encryption is considered enabled if either the environment
        # variable is set or a db_encryption_secret exists in settings.
        'db_encrypted': bool(
            os.environ.get('FAKEICAP_KEY_SECRET')
            or settings.get('db_encryption_secret')
        ),
    }
    try:
        cursor = conn.cursor()
        try:
            row = cursor.execute(
                "SELECT fingerprint, created_at FROM pgp_keys WHERE is_active = 1 ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                pgp_status['active_fingerprint'] = row['fingerprint']
                pgp_status['created_at'] = row['created_at']
            count_row = cursor.execute("SELECT COUNT(*) AS cnt FROM pgp_keys").fetchone()
            if count_row:
                # sqlite3.Row supports both index and key access
                pgp_status['total_keys'] = count_row[0]
        except sqlite3.OperationalError:
            # pgp_keys table might not exist yet; leave status at defaults
            pass
    finally:
        conn.close()

    server_hosts = get_available_ipv4_addresses()

    return render_template(
        'settings.html',
        settings=settings,
        server_hosts=server_hosts,
        pgp_status=pgp_status,
    )


@app.route('/no_access')
def no_access():
    """Informational page for users without an assigned access role."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('no_access.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))

        # Enforce password complexity policy
        ok, message = validate_password_complexity(new_password)
        if not ok:
            flash(message, 'error')
            return redirect(url_for('change_password'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password_hash'], current_password):
            conn.close()
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))

        password_hash = generate_password_hash(new_password)
        cursor.execute(
            'UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?',
            (password_hash, session['user_id'])
        )
        conn.commit()
        conn.close()

        # Hide default credentials hint after admin updates their password
        try:
            if session.get('is_admin') and session.get('user_id') == 1:
                conn2 = get_db_connection()
                if conn2:
                    cur2 = conn2.cursor()
                    cur2.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES ('show_default_credentials_hint', '0')"
                    )
                    conn2.commit()
                    conn2.close()
        except Exception:
            pass

        session['must_change_password'] = False
        flash('Password changed successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('change_password.html')

@app.route('/users')
def users():
    """User management page (admin only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to view users.', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    rows = conn.execute('''
        SELECT id, username, is_admin, must_change_password, created_at, last_login, role
        FROM users
        ORDER BY username
    ''').fetchall()
    
    users_list = []
    for row in rows:
        db_role = row['role'] if 'role' in row.keys() else ROLE_FULL_ACCESS
        if row['id'] == 1 or row['is_admin']:
            db_role = ROLE_ADMIN

        if db_role == ROLE_ADMIN:
            role_label = 'Admin'
        elif db_role == ROLE_FULL_ACCESS:
            role_label = 'Full Access'
        elif db_role == ROLE_LOG_VIEWER:
            role_label = 'Log Viewer'
        elif db_role == ROLE_FILE_DOWNLOAD:
            role_label = 'File Download'
        elif db_role == ROLE_NO_ACCESS:
            role_label = 'No Access (Pending Approval)'
        else:
            role_label = 'Full Access'

        users_list.append({
            'id': row['id'],
            'username': row['username'],
            'is_admin': bool(row['is_admin']),
            'must_change_password': bool(row['must_change_password']),
            'created_at': row['created_at'],
            'last_login': row['last_login'],
            'is_default_admin': row['id'] == 1,
            'role': db_role,
            'role_label': role_label,
        })

    # Load password policy settings
    settings_rows = conn.execute('SELECT key, value FROM settings').fetchall()
    conn.close()
    settings = {row['key']: row['value'] for row in settings_rows}

    return render_template('users.html', users=users_list, settings=settings)

@app.route('/add_user', methods=['POST'])
def add_user():
    """Add a new user (admin only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to add users.', 'error')
        return redirect(url_for('index'))

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    is_admin = 1 if request.form.get('is_admin') == 'on' else 0
    raw_role = (request.form.get('role') or '').strip().upper()
    must_change_password = 1 if request.form.get('must_change_password') == 'on' else 0

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('users'))

    # Enforce password complexity policy
    ok, message = validate_password_complexity(password)
    if not ok:
        flash(message, 'error')
        return redirect(url_for('users'))

    # Determine role based on admin flag and requested role
    if is_admin:
        role = ROLE_ADMIN
    else:
        valid_roles = {ROLE_FULL_ACCESS, ROLE_LOG_VIEWER, ROLE_FILE_DOWNLOAD, ROLE_NO_ACCESS}
        role = raw_role if raw_role in valid_roles else ROLE_FULL_ACCESS

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        password_hash = generate_password_hash(password)
        cursor.execute(
            'INSERT INTO users (username, password_hash, is_admin, must_change_password, created_at, role) VALUES (?, ?, ?, ?, ?, ?)',
            (username, password_hash, is_admin, must_change_password, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), role)
        )
        conn.commit()
        flash('User created successfully.', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists.', 'error')
    finally:
        conn.close()

    return redirect(url_for('users'))

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    """Delete a user (admin only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to delete users.', 'error')
        return redirect(url_for('index'))

    # Never allow deleting the default admin
    if user_id == 1:
        flash('Cannot delete the default admin user.', 'error')
        return redirect(url_for('users'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully.', 'success')
    return redirect(url_for('users'))

@app.route('/reset_user_password/<int:user_id>', methods=['POST'])
def reset_user_password(user_id):
    """Reset a user's password (admin only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to reset passwords.', 'error')
        return redirect(url_for('index'))

    new_password = request.form.get('new_password') or ''
    must_change_password = 1 if request.form.get('must_change_password') == 'on' else 0

    if not new_password:
        flash('New password is required.', 'error')
        return redirect(url_for('users'))

    # Enforce password complexity policy
    ok, message = validate_password_complexity(new_password)
    if not ok:
        flash(message, 'error')
        return redirect(url_for('users'))

    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = generate_password_hash(new_password)
    cursor.execute(
        'UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?',
        (password_hash, must_change_password, user_id)
    )
    conn.commit()
    conn.close()

    flash('User password reset successfully.', 'success')
    return redirect(url_for('users'))

@app.route('/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    """Edit an existing user (admin only). Allows changing username and role.

    The default admin (id=1) cannot be deleted but the username can be changed,
    and they must always retain admin privileges.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        flash('Admin privileges are required to edit users.', 'error')
        return redirect(url_for('index'))

    username = (request.form.get('username') or '').strip()
    is_admin_flag = 1 if request.form.get('is_admin') == 'on' else 0
    raw_role = (request.form.get('role') or '').strip().upper()

    if not username:
        flash('Username is required.', 'error')
        return redirect(url_for('users'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if user_id == 1:
            # Default admin must always remain an admin
            cursor.execute(
                'UPDATE users SET username = ?, is_admin = 1, role = ? WHERE id = ?',
                (username, ROLE_ADMIN, user_id),
            )
        else:
            # Determine role based on admin flag and requested role
            if is_admin_flag:
                role = ROLE_ADMIN
            else:
                valid_roles = {ROLE_FULL_ACCESS, ROLE_LOG_VIEWER, ROLE_FILE_DOWNLOAD, ROLE_NO_ACCESS}
                role = raw_role if raw_role in valid_roles else ROLE_FULL_ACCESS

            cursor.execute(
                'UPDATE users SET username = ?, is_admin = ?, role = ? WHERE id = ?',
                (username, is_admin_flag, role, user_id),
            )
        conn.commit()
        flash('User updated successfully.', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists.', 'error')
    finally:
        conn.close()

    # Keep session data in sync if the current user was edited
    if session.get('user_id') == user_id:
        session['username'] = username
        if user_id == 1:
            session['is_admin'] = True
            session['role'] = ROLE_ADMIN
        else:
            session['is_admin'] = bool(is_admin_flag)
            if session['is_admin']:
                session['role'] = ROLE_ADMIN
            else:
                # Keep session role in sync with updated DB role
                session['role'] = role

    return redirect(url_for('users'))

def run_transfer_cleanup():
    """Background thread to clean up incomplete transfers"""
    if logger is not None:
        logger.app_logger.info("Transfer cleanup thread started")
    else:
        print("Transfer cleanup thread started")
    while True:
        try:
            count = len(ongoing_transfers)
            if logger is not None:
                logger.app_logger.debug(f"Checking {count} ongoing transfers...")
            cleanup_incomplete_transfers()
            time.sleep(2)  # Check every 2 seconds
        except Exception as e:
            if logger is not None:
                logger.app_logger.error(f"Error in transfer cleanup: {e}")
            else:
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
        
        # Load configuration from database settings
        server_host = get_server_host()
        server_port = get_server_port()
        logger.app_logger.info(f"Loaded configuration: host={server_host}, port={server_port}")
        
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
