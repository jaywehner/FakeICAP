#!/usr/bin/env python3
"""
Minimal ICAP server that responds to any connection immediately
This is designed to work around network connectivity issues
"""

import socket
import time
import os
import re
import uuid
from datetime import datetime

def create_date_directory_structure(base_path):
    """Create directory structure: saved_files/YYYY/MM/DD/"""
    try:
        now = datetime.now()
        year = str(now.year)
        month = f"{now.month:02d}"
        day = f"{now.day:02d}"
        
        # Create the full directory path
        dir_path = os.path.join(base_path, year, month, day)
        
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
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'\.\.', '_', filename)
    
    # Limit length
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:95] + ext
    
    return filename.strip()

def extract_file_info_from_icap(data):
    """Extract file information from ICAP request headers"""
    try:
        data_str = data.decode('utf-8', errors='ignore')
        lines = data_str.split('\r\n')
        
        file_info = {
            'method': '',
            'filename': '',
            'content_length': 0,
            'path': '',
            'host': ''
        }
        
        # Parse ICAP request line
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                file_info['method'] = parts[0]
        
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
            elif line.startswith('HTTP/1.1 200 OK') or line.startswith('HTTP/1.0 200 OK'):
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
                            print(f"Found Content-Length: {header_value}")
                        except ValueError:
                            print(f"Invalid Content-Length: {header_value}")
                    elif header_name == 'host' and not file_info['host']:
                        file_info['host'] = header_value
                elif line == '':  # End of HTTP headers
                    break
        
        print(f"Extracted file info: {file_info}")
        return file_info
    except Exception as e:
        print(f"Error extracting file info: {e}")
        return None

def receive_file_content(client_socket, file_info):
    """Try to receive the actual file content from GoAnywhere"""
    try:
        print("Attempting to receive file content...")
        
        # Set a reasonable timeout for file content
        client_socket.settimeout(15.0)
        
        # Try to receive more data (the actual file content)
        additional_data = b""
        expected_size = file_info.get('content_length', 0)
        
        try:
            while len(additional_data) < expected_size or expected_size == 0:
                chunk = client_socket.recv(8192)
                if not chunk:
                    break
                additional_data += chunk
                print(f"Received chunk: {len(chunk)} bytes (total: {len(additional_data)})")
                
                # Safety limit to prevent memory issues
                if len(additional_data) > 50000000:  # 50MB limit
                    print("Reached safety size limit, stopping reception")
                    break
                
                # If we have the expected size, stop
                if expected_size > 0 and len(additional_data) >= expected_size:
                    print("Received expected amount of data")
                    break
                    
        except socket.timeout:
            print("Timeout receiving file content")
        except Exception as e:
            print(f"Error receiving file content: {e}")
        
        if additional_data:
            print(f"Total file content received: {len(additional_data)} bytes")
            return additional_data
        else:
            print("No file content received")
            return None
            
    except Exception as e:
        print(f"Error in receive_file_content: {e}")
        return None

def save_file_and_record(file_info, file_content):
    """Save both the file and its record using the same GUID"""
    try:
        if not file_info or not file_content:
            print("Missing file info or content")
            return None, None
        
        # Create base saved_files directory if it doesn't exist
        if not os.path.exists('saved_files'):
            os.makedirs('saved_files')
        
        # Create date-based directory structure
        target_dir = create_date_directory_structure('saved_files')
        
        # Generate GUID for unique identification (used for both file and record)
        shared_guid = str(uuid.uuid4())
        
        # Get original filename and sanitize it
        original_filename = file_info.get('filename', 'unknown_file')
        safe_filename = sanitize_filename(original_filename)
        
        # Extract file extension
        if '.' in safe_filename:
            base_name, extension = os.path.splitext(safe_filename)
        else:
            base_name = safe_filename
            extension = '.bin'
        
        # Create file and record filenames with the same GUID
        file_filename = f"{shared_guid}_{base_name}{extension}"
        record_filename = f"record_{shared_guid}.txt"
        
        file_path = os.path.join(target_dir, file_filename)
        record_path = os.path.join(target_dir, record_filename)
        
        # Save the file content
        try:
            with open(file_path, 'wb') as f:
                f.write(file_content)
            print(f"File saved successfully: {file_filename} ({len(file_content)} bytes)")
            print(f"File path: {file_path}")
        except IOError as e:
            print(f"Failed to write file {file_path}: {e}")
            return None, None
        
        # Save the record with the same GUID
        try:
            with open(record_path, 'w') as f:
                f.write(f"ICAP File Processing Record\n")
                f.write(f"Record ID: {shared_guid}\n")
                f.write(f"Corresponding File: {file_filename}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Method: {file_info.get('method', 'Unknown')}\n")
                f.write(f"Filename: {file_info.get('filename', 'Unknown')}\n")
                f.write(f"Path: {file_info.get('path', 'Unknown')}\n")
                f.write(f"Host: {file_info.get('host', 'Unknown')}\n")
                f.write(f"Content Length: {file_info.get('content_length', 0)} bytes\n")
                f.write(f"Status: Processed (204 No Content)\n")
            
            print(f"File record saved: {record_filename}")
            print(f"Record path: {record_path}")
        except IOError as e:
            print(f"Failed to write record {record_path}: {e}")
            return file_path, None
        
        return file_path, record_path
        
    except Exception as e:
        print(f"Error in save_file_and_record: {e}")
        return None, None

def get_current_gmt_time():
    """Get current GMT time in ICAP format"""
    return datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

def minimal_icap_server():
    """Minimal ICAP server that responds immediately to prevent hangs"""
    host = 'YOUR_SERVER_IP'  # Replace with your actual server IP
    port = 1344
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(5)
        
        print(f"=== MINIMAL ICAP SERVER listening on {host}:{port} ===")
        print("This server responds immediately to any connection")
        
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                print(f"=== CONNECTION from {client_address} ===")
                
                # Set a very short timeout
                client_socket.settimeout(1.0)
                
                # Try to receive some data
                try:
                    data = client_socket.recv(4096)  # Increased buffer size
                    print(f"Received {len(data)} bytes")
                    if data:
                        print(f"Data preview: {data[:300]}...")
                        
                        # Extract file information
                        file_info = extract_file_info_from_icap(data)
                        if file_info:
                            print(f"File info: {file_info}")
                        
                        # Check if it's ICAP and respond appropriately
                        data_str = data.decode('utf-8', errors='ignore')
                        if 'OPTIONS' in data_str:
                            response = f"""ICAP/1.0 200 OK\r
Date: {get_current_gmt_time()}\r
Server: MinimalICAP/1.0\r
Connection: close\r
ISTag: "Minimal-001"\r
Methods: REQMOD, RESPMOD, OPTIONS\r
Allow: 204\r
Service: MinimalICAP/1.0 "Minimal ICAP Server"\r
Encapsulated: null-body=0\r
\r
\r
""".encode('utf-8')
                        elif 'RESPMOD' in data_str:
                            # Check if this is a preview request
                            if 'preview:' in data_str and 'preview: 0' not in data_str:
                                # This is a preview request, respond with 100 Continue
                                response = f"""ICAP/1.0 100 Continue\r
Date: {get_current_gmt_time()}\r
Server: MinimalICAP/1.0\r
Connection: keep-alive\r
ISTag: "Minimal-001"\r
\r
\r
""".encode('utf-8')
                                print("Preview request - responding with 100 Continue")
                            else:
                                # This is the full content request, try to receive the file
                                print("Full RESPMOD request - attempting to receive file content")
                                file_content = receive_file_content(client_socket, file_info)
                                if file_content:
                                    file_path, record_path = save_file_and_record(file_info, file_content)
                                    if file_path and record_path:
                                        print(f"Successfully saved file and record with matching GUIDs")
                                
                                response = f"""ICAP/1.0 204 No Content\r
Date: {get_current_gmt_time()}\r
Server: MinimalICAP/1.0\r
Connection: close\r
ISTag: "Minimal-001"\r
Encapsulated: null-body=0\r
\r
\r
""".encode('utf-8')
                        else:
                            response = f"""ICAP/1.0 400 Bad Request\r
Date: {get_current_gmt_time()}\r
Server: MinimalICAP/1.0\r
Connection: close\r
\r
\r
""".encode('utf-8')
                        
                        client_socket.send(response)
                        print("Response sent")
                except socket.timeout:
                    print("Timeout receiving data, sending default response")
                    # Send a default 204 response
                    response = f"""ICAP/1.0 204 No Content\r
Date: {get_current_gmt_time()}\r
Server: MinimalICAP/1.0\r
Connection: close\r
ISTag: "Minimal-001"\r
Encapsulated: null-body=0\r
\r
\r
""".encode('utf-8')
                    client_socket.send(response)
                
                client_socket.close()
                print("Connection closed")
                
            except Exception as e:
                print(f"Error: {e}")
                
    except Exception as e:
        print(f"Failed to start server: {e}")

if __name__ == "__main__":
    minimal_icap_server()
