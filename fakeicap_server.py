#!/usr/bin/env python3
"""
FakeICAP Server - A minimal ICAP server that accepts file submissions
and saves them locally without actual virus scanning.

Implements ICAP protocol according to RFC 3507
Listens on port 1344
"""

import socket
import threading
import time
import os
import hashlib
from datetime import datetime
from urllib.parse import unquote


class FakeICAPServer:
    def __init__(self, host='YOUR_SERVER_IP', port=1344):  # Replace YOUR_SERVER_IP with your actual server IP
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.saved_files_dir = "saved_files"
        
        # Create directory for saved files if it doesn't exist
        if not os.path.exists(self.saved_files_dir):
            os.makedirs(self.saved_files_dir)
    
    def start(self):
        """Start the ICAP server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Try to bind to the port
            try:
                self.server_socket.bind((self.host, self.port))
            except socket.error as e:
                print(f"Failed to bind to {self.host}:{self.port} - {e}")
                print("This might be due to:")
                print("1. Port 1344 is already in use by another application")
                print("2. Insufficient permissions to bind to the port")
                print("3. Firewall blocking the connection")
                return False
                
            self.server_socket.listen(5)
            self.running = True
            
            print(f"FakeICAP Server successfully started on {self.host}:{self.port}")
            print(f"Files will be saved to: {self.saved_files_dir}/")
            print("Waiting for ICAP connections...")
            
            while self.running:
                try:
                    print(f"=== WAITING FOR CONNECTION on {self.host}:{self.port} ===")
                    client_socket, client_address = self.server_socket.accept()
                    print(f"=== RAW CONNECTION ACCEPTED from {client_address} ===")
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"Socket error in accept: {e}")
                    break
                    
        except Exception as e:
            print(f"Failed to start server: {e}")
            return False
        finally:
            self.stop()
        
        return True
    
    def stop(self):
        """Stop the ICAP server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("FakeICAP Server stopped")
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        connection_id = f"{client_address[0]}:{client_address[1]}"
        print(f"=== NEW CONNECTION {connection_id} ===")
        
        try:
            # Log connection details
            print(f"Remote address: {client_address}")
            print(f"Socket timeout: {client_socket.gettimeout()}")
            
            # Receive ICAP request
            request_data = self.receive_icap_request(client_socket)
            if not request_data:
                print(f"=== CONNECTION {connection_id}: No data received ===")
                return
            
            print(f"=== CONNECTION {connection_id}: Received {len(request_data)} bytes ===")
            print(f"Request preview: {request_data[:500]}...")
            
            # Parse ICAP request
            parsed_request = self.parse_icap_request(request_data)
            if not parsed_request:
                print(f"=== CONNECTION {connection_id}: Failed to parse request ===")
                return
            
            print(f"=== CONNECTION {connection_id}: Parsed successfully ===")
            print(f"Method: {parsed_request['method']}")
            print(f"URL: {parsed_request['url']}")
            print(f"Headers: {len(parsed_request['headers'])}")
            print(f"Body length: {len(parsed_request.get('body', ''))}")
            
            # Process based on ICAP method
            response = self.process_icap_request(parsed_request, request_data)
            
            # Send ICAP response
            print(f"=== CONNECTION {connection_id}: Sending response ===")
            client_socket.send(response.encode('utf-8'))
            print(f"=== CONNECTION {connection_id}: Response sent ===")
            
        except Exception as e:
            print(f"=== CONNECTION {connection_id}: ERROR ===")
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            
            # Send error response
            error_response = self.create_error_response("500 ICAP Internal Server Error")
            try:
                client_socket.send(error_response.encode('utf-8'))
                print(f"=== CONNECTION {connection_id}: Error response sent ===")
            except Exception as send_error:
                print(f"=== CONNECTION {connection_id}: Failed to send error response: {send_error} ===")
        finally:
            try:
                client_socket.close()
                print(f"=== CONNECTION {connection_id}: Closed ===")
            except:
                pass
    
    def receive_icap_request(self, client_socket):
        """Receive complete ICAP request from client"""
        request_data = b""
        
        try:
            # Set a reasonable timeout for initial headers
            client_socket.settimeout(5.0)
            
            # Receive initial chunk to get headers
            while b"\r\n\r\n" not in request_data:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_data += chunk
            
            if not request_data:
                return None
            
            print(f"=== INITIAL REQUEST RECEIVED: {len(request_data)} bytes ===")
            print(f"Request preview: {request_data[:300]}...")
            
            # Parse headers to check if this is RESPMOD with preview
            headers_str = request_data.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
            headers = headers_str.split('\r\n')
            
            preview_length = 0
            for header in headers:
                if header.lower().startswith('preview:'):
                    preview_length = int(header.split(':', 1)[1].strip())
                    break
            
            # If this is RESPMOD with preview, we need to handle the two-phase protocol
            if 'RESPMOD' in headers_str and preview_length > 0:
                print(f"RESPMOD with preview {preview_length} detected")
                print("This is the initial preview request, returning it for processing")
                return request_data.decode('utf-8', errors='ignore')
            
            # For other requests, return what we have
            return request_data.decode('utf-8', errors='ignore')
            
        except socket.timeout:
            print("Timeout receiving request - processing what we have")
            if request_data:
                return request_data.decode('utf-8', errors='ignore')
            return None
        except Exception as e:
            print(f"Error receiving ICAP request: {e}")
            if request_data:
                return request_data.decode('utf-8', errors='ignore')
            return None
    
    def parse_encapsulated_header(self, encapsulated_str):
        """Parse the Encapsulated header to get body offsets"""
        parts = encapsulated_str.split(',')
        info = {}
        
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                info[key.strip()] = int(value.strip())
        
        return info
    
    def parse_icap_request(self, request_data):
        """Parse ICAP request into components"""
        lines = request_data.split('\r\n')
        
        if not lines:
            return None
        
        # Parse request line
        request_line = lines[0].strip()
        parts = request_line.split()
        
        if len(parts) < 3:
            return None
        
        method = parts[0]
        url = parts[1]
        version = parts[2]
        
        # Parse headers
        headers = {}
        body_start = -1
        
        print("=== ICAP Headers Received ===")
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
                print(f"{key.strip()}: {value.strip()}")
        print("=== End Headers ===")
        
        # Extract body if present
        body = ""
        if body_start > 0 and body_start < len(lines):
            body = '\r\n'.join(lines[body_start:])
        
        return {
            'method': method,
            'url': url,
            'version': version,
            'headers': headers,
            'body': body,
            'raw_request': request_data
        }
    
    def process_icap_request(self, parsed_request, raw_request):
        """Process ICAP request and return appropriate response"""
        if not parsed_request:
            return self.create_error_response("400 Bad Request")
        
        method = parsed_request['method']
        url = parsed_request['url']
        
        # Extract service name from URL (everything after the host:port)
        service_name = ""
        if '://' in url:
            url_parts = url.split('://', 1)[1]  # Remove protocol
            if '/' in url_parts:
                service_name = '/' + url_parts.split('/', 1)[1]
            else:
                service_name = '/'
        
        print(f"ICAP Method: {method}")
        print(f"Service: {service_name}")
        
        if method == 'OPTIONS':
            response = self.create_options_response(service_name)
            print(f"OPTIONS Response being sent:")
            print("=" * 50)
            print(response)
            print("=" * 50)
            return response
        elif method == 'REQMOD':
            return self.handle_reqmod(parsed_request, raw_request)
        elif method == 'RESPMOD':
            return self.handle_respmod(parsed_request, raw_request)
        else:
            return self.create_error_response("405 Method Not Allowed")
    
    def handle_reqmod(self, parsed_request, raw_request):
        """Handle REQMOD requests - extract and save files"""
        try:
            # Extract file from the encapsulated HTTP request
            saved_file_info = self.extract_and_save_file(parsed_request)
            
            if saved_file_info:
                print(f"File saved: {saved_file_info['filename']} ({saved_file_info['size']} bytes)")
                # Return OK response with the original request
                return self.create_ok_response(parsed_request)
            else:
                print("No file found in request")
                return self.create_ok_response(parsed_request)
                
        except Exception as e:
            print(f"Error in REQMOD handler: {e}")
            return self.create_error_response("500 ICAP Internal Server Error")
    
    def handle_respmod(self, parsed_request, raw_request):
        """Handle RESPMOD requests - respond with 100 Continue per GoAnywhere docs"""
        try:
            print("=== Processing RESPMOD Request ===")
            
            # Check if this is a preview request
            preview_header = parsed_request.get('headers', {}).get('preview', '0')
            if preview_header != '0':
                print(f"Preview request detected: {preview_header} bytes")
                print("Responding with 100 Continue to get full file content")
                # For preview requests, respond with 100 Continue per GoAnywhere documentation
                return self.create_continue_response()
            else:
                print("No preview - responding with 204 No Content")
                # Return 204 No Content to indicate we don't need to modify the response
                return self.create_no_content_response()
                
        except Exception as e:
            print(f"Error in RESPMOD handler: {e}")
            import traceback
            traceback.print_exc()
            return self.create_error_response("500 ICAP Internal Server Error")
    
    def extract_and_save_file_from_response(self, parsed_request):
        """Extract file from HTTP response body and save it"""
        try:
            body = parsed_request.get('body', '')
            if not body:
                return None
            
            print(f"RESPMOD body length: {len(body)}")
            print(f"RESPMOD body preview: {body[:200]}...")
            
            # Parse the encapsulated HTTP response to find file data
            # RESPMOD format: req-hdr=0, res-hdr=X, res-body=Y
            encapsulated_header = parsed_request.get('headers', {}).get('encapsulated', '')
            print(f"Encapsulated header: {encapsulated_header}")
            
            # Parse the encapsulated parts
            parts = encapsulated_header.split(',')
            offsets = {}
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    offsets[key.strip()] = int(value.strip())
            
            print(f"Offsets: {offsets}")
            
            # Find the response body start
            res_body_offset = offsets.get('res-body', 0)
            if res_body_offset > 0 and len(body) > res_body_offset:
                file_data = body[res_body_offset:]
                
                # Try to parse the actual HTTP response body
                http_lines = file_data.split('\r\n')
                
                # Find the start of actual file content (after HTTP headers)
                content_start = -1
                content_length = 0
                
                for i, line in enumerate(http_lines):
                    if line.lower().startswith('content-length:'):
                        content_length = int(line.split(':', 1)[1].strip())
                    elif line == '':  # Empty line marks start of body
                        content_start = i + 1
                        break
                
                if content_start != -1:
                    actual_file_data = '\r\n'.join(http_lines[content_start:])
                    if len(actual_file_data) > content_length:
                        actual_file_data = actual_file_data[:content_length]
                    
                    print(f"Extracted file data length: {len(actual_file_data)}")
                    
                    # Generate filename
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    content_hash = hashlib.md5(actual_file_data.encode('utf-8', errors='ignore')).hexdigest()[:8]
                    filename = f"respmod_file_{timestamp}_{content_hash}.log"
                    filepath = os.path.join(self.saved_files_dir, filename)
                    
                    # Save file
                    with open(filepath, 'wb') as f:
                        f.write(actual_file_data.encode('utf-8', errors='ignore'))
                    
                    return {
                        'filename': filename,
                        'filepath': filepath,
                        'size': len(actual_file_data),
                        'content_type': 'application/octet-stream'
                    }
            
            return None
            
        except Exception as e:
            print(f"Error extracting file from RESPMOD: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def extract_and_save_file(self, parsed_request):
        """Extract file from HTTP request body and save it"""
        try:
            body = parsed_request.get('body', '')
            if not body:
                return None
            
            # Parse the encapsulated HTTP request to find file data
            http_lines = body.split('\r\n')
            
            # Find Content-Type and Content-Length in the HTTP request
            content_type = ""
            content_length = 0
            file_data_start = -1
            
            for i, line in enumerate(http_lines):
                line_lower = line.lower()
                if line_lower.startswith('content-type:'):
                    content_type = line.split(':', 1)[1].strip()
                elif line_lower.startswith('content-length:'):
                    content_length = int(line.split(':', 1)[1].strip())
                elif line == '':  # Empty line marks start of body
                    file_data_start = i + 1
                    break
            
            if file_data_start == -1 or content_length == 0:
                return None
            
            # Extract file data
            file_data = '\r\n'.join(http_lines[file_data_start:])
            
            # Handle chunked encoding or other formats
            if len(file_data) > content_length:
                file_data = file_data[:content_length]
            
            # Generate filename based on timestamp and content hash
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            content_hash = hashlib.md5(file_data.encode('utf-8', errors='ignore')).hexdigest()[:8]
            
            # Try to determine file extension from content type
            extension = ".bin"
            if 'multipart/form-data' in content_type:
                # Extract filename from multipart data
                if 'filename=' in content_type:
                    filename_part = content_type.split('filename=')[1].strip()
                    filename = unquote(filename_part.strip('"'))
                    if '.' in filename:
                        extension = '.' + filename.split('.')[-1]
            elif 'text/plain' in content_type:
                extension = ".txt"
            elif 'application/pdf' in content_type:
                extension = ".pdf"
            elif 'image/jpeg' in content_type:
                extension = ".jpg"
            elif 'image/png' in content_type:
                extension = ".png"
            
            filename = f"file_{timestamp}_{content_hash}{extension}"
            filepath = os.path.join(self.saved_files_dir, filename)
            
            # Save file
            with open(filepath, 'wb') as f:
                f.write(file_data.encode('utf-8', errors='ignore'))
            
            return {
                'filename': filename,
                'filepath': filepath,
                'size': len(file_data),
                'content_type': content_type
            }
            
        except Exception as e:
            print(f"Error extracting file: {e}")
            return None
    
    def create_no_content_response(self):
        """Create ICAP 204 No Content response"""
        response_lines = [
            "ICAP/1.0 204 No Content",
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}",
            "Server: FakeICAP/1.0",
            "Connection: keep-alive",
            "ISTag: \"FakeICAP-001\"",
            "Encapsulated: null-body=0",
            "",
            ""
        ]
        return "\r\n".join(response_lines)
    
    def create_continue_response(self):
        """Create ICAP 100 Continue response for preview requests"""
        response_lines = [
            "ICAP/1.0 100 Continue",
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}",
            "Server: FakeICAP/1.0",
            "ISTag: \"FakeICAP-001\"",
            "",
            ""
        ]
        return "\r\n".join(response_lines)
    
    def create_options_response(self, service_name="/"):
        """Create ICAP OPTIONS response"""
        response_lines = [
            "ICAP/1.0 200 OK",
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}",
            "Server: FakeICAP/1.0",
            "Connection: keep-alive",
            "ISTag: \"FakeICAP-001\"",
            "Methods: REQMOD, RESPMOD, OPTIONS",
            "Allow: 204",
            "Service: FakeICAP/1.0 \"Fake ICAP Server for File Submission\"",
            "Max-Connections: 100",
            "Options-TTL: 3600",
            "X-Include: Referer, User-Agent, Cookie, Authorization",
            "Preview: 0",
            "Transfer-Preview: none",
            "Encapsulated: null-body=0",
            "",
            ""
        ]
        return "\r\n".join(response_lines)
    
    def create_ok_response(self, parsed_request):
        """Create ICAP OK response that returns the original request"""
        # For REQMOD, we return the original request unmodified
        if parsed_request['method'] == 'REQMOD':
            body = parsed_request.get('body', '')
            headers_end = parsed_request['raw_request'].find('\r\n\r\n')
            headers = parsed_request['raw_request'][:headers_end]
            
            response = f"""ICAP/1.0 200 OK
Date: {time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}
Server: FakeICAP/1.0
ISTag: "FakeICAP-001"
Encapsulated: req-hdr=0, req-body={len(headers) + 4}

{headers}

{body}"""
        else:
            # For RESPMOD or other methods
            response = f"""ICAP/1.0 200 OK
Date: {time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}
Server: FakeICAP/1.0
ISTag: "FakeICAP-001"
Encapsulated: null-body=0

"""
        
        return response
    
    def create_error_response(self, error_code):
        """Create ICAP error response"""
        response = f"""ICAP/1.0 {error_code}
Date: {time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}
Server: FakeICAP/1.0
ISTag: "FakeICAP-001"
Encapsulated: null-body=0

"""
        return response


def main():
    """Main function to start the FakeICAP server"""
    server = FakeICAPServer()
    
    try:
        print("Starting FakeICAP Server...")
        print("Press Ctrl+C to stop the server")
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()


if __name__ == "__main__":
    main()
