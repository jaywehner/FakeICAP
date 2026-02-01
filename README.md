# FakeICAP Server

A minimal ICAP (Internet Content Adaptation Protocol) server that accepts file submissions and saves them locally without performing actual virus scanning.

## Features

- **ICAP Protocol Compliance**: Implements ICAP protocol according to [RFC 3507](https://datatracker.ietf.org/doc/html/rfc3507)
- **GoAnywhere Compatible**: Specifically tested and optimized for GoAnywhere MFT integration
- **Network Resilient**: Minimal implementation that works around connectivity issues
- **File Extraction**: Extracts and saves files from ICAP RESPMOD requests
- **Automatic File Naming**: Generates unique filenames with timestamps
- **Processing Records**: Creates detailed logs of all processed files
- **No External Dependencies**: Uses only Python standard library

## Quick Start

1. **Start the server:**
   ```bash
   python minimal_icap.py
   ```

2. **Server will start listening on port 1344:**
   ```
   === MINIMAL ICAP SERVER listening on YOUR_SERVER_IP:1344 ===
   This server responds immediately to any connection
   ```

3. **Configure GoAnywhere MFT:**
   - **Host:** `YOUR_SERVER_IP` (replace with your actual server IP)
   - **Port:** `1344`
   - **Service:** `/` (root service)

## ICAP Protocol Support

### Supported Methods
- **OPTIONS**: Returns server capabilities and supported methods
- **RESPMOD**: Response modification for file scanning
- **REQMOD**: Request modification (basic support)

### Response Codes
- **100 Continue**: Sent for preview requests to receive full content
- **200 OK**: Successful OPTIONS response
- **204 No Content**: File processed successfully (no modifications needed)
- **400 Bad Request**: Invalid ICAP request

### Two-Phase Processing
1. **Preview Phase**: Server responds with `100 Continue` to request full file content
2. **Content Phase**: Server receives actual file data and saves it locally
3. **Completion Phase**: Server responds with `204 No Content` indicating successful processing

## File Storage

### File Organization
Files are saved to the `saved_files/` directory with the following naming convention:

```
file_YYYYMMDD_HHMMSS_original_filename.ext
```

**Example:**
```
file_20250129_143427_goanywhere.log
```

### Processing Records
For each processed file, a detailed record is created:

```
file_record_YYYYMMDD_HHMMSS.txt
```

**Record Contents:**
- Timestamp
- ICAP method used
- Original filename
- File path
- Host information
- Content length
- Processing status

## Network Compatibility

This implementation is specifically designed to overcome common ICAP connectivity issues:

### Problem Solved
- **RESPMOD Connection Drops**: Many networks block or drop RESPMOD connections
- **Large File Transfers**: Standard ICAP servers hang on large file transfers
- **Timeout Issues**: Complex ICAP implementations cause client timeouts

### Solution Approach
- **Minimal Response**: Immediate responses prevent client hanging
- **Header-First Processing**: Extracts file information before receiving content
- **Adaptive Timeouts**: Different timeouts for headers vs. content
- **Error Resilience**: Graceful handling of network interruptions

## Configuration

FakeICAP supports multiple configuration methods with the following priority:

### 1. Local Config File (Highest Priority)
For local development, create a `config.py` file:

```bash
cp config.local.example.py config.py
# Edit config.py with your settings
```

**Example `config.py`:**
```python
SERVER_HOST = '192.168.1.100'  # Your server IP
SERVER_PORT = 1344               # ICAP port
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit
FILE_TIMEOUT = 15                # Timeout in seconds
```

### 2. Database Settings (Web Interface)
Configure through the web dashboard at `http://localhost:5000`:
- **Server Host:** IP address for ICAP server
- **Server Port:** Port for ICAP server (default: 1344)
- **File Settings:** Size limits and timeouts
- **Logging:** Rotation and retention policies

### 3. Default Values (Lowest Priority)
If no configuration is found, these defaults are used:
- **Host:** `0.0.0.0` (all interfaces)
- **Port:** `1344`
- **Max File Size:** 50MB
- **Timeout:** 15 seconds

### Configuration Priority
1. **config.py** file (local development)
2. **Database settings** (web interface)
3. **Default values** (fallback)

### Security Notes
- `config.py` is automatically ignored by Git
- Keep local configuration files private
- Use different configs for development vs production
- Database settings work well for team environments

## GoAnywhere MFT Integration

### Required GoAnywhere Settings
1. **ICAP Server Configuration:**
   - Server IP: `YOUR_SERVER_IP` (replace with your actual server IP)
   - Port: `1344`
   - Service: `/`

2. **ICAP Task Settings:**
   - Content Type: Auto-detected from file
   - Response Body: Optional (for debugging)
   - Response Headers: Optional (for debugging)

### Expected GoAnywhere Behavior
1. **OPTIONS Request**: Server capabilities retrieved successfully
2. **RESPMOD Request**: File scanning request processed
3. **100 Continue**: Server requests full file content
4. **File Transfer**: File content received and saved
5. **204 Response**: Processing completed successfully
6. **Job Completion**: GoAnywhere continues with next task

## Troubleshooting

### Common Issues

**Connection Refused**
- Ensure server is running on correct IP and port
- Check firewall settings on port 1344
- Verify GoAnywhere can reach the server IP

**File Not Saved**
- Check `saved_files/` directory permissions
- Verify file content was actually transmitted
- Review server logs for processing errors

**GoAnywhere Timeout**
- Network connectivity issues between GoAnywhere and server
- Large files exceeding timeout limits
- ICAP protocol mismatches

### Debugging
- **Server Logs**: Detailed connection and processing information
- **File Records**: Processing status for each file
- **Network Testing**: Use `test_connection.py` for connectivity testing

## Security Considerations

### File Safety
- **Filename Sanitization**: Prevents path traversal attacks
- **Size Limits**: Prevents denial of service via large files
- **Content Validation**: Basic file type detection

### Network Security
- **Minimal Exposure**: Only necessary ICAP endpoints
- **No External Services**: No outbound connections
- **Local Storage**: Files saved only to local directory

## API Reference

### ICAP Endpoints

#### OPTIONS
```
OPTIONS icap://YOUR_SERVER_IP:1344/ ICAP/1.0
Host: YOUR_SERVER_IP
User-Agent: GoAnywhere
Encapsulated: null-body=0
```

**Response:**
```
ICAP/1.0 200 OK
Date: [Current GMT]
Server: MinimalICAP/1.0
Connection: close
ISTag: "Minimal-001"
Methods: REQMOD, RESPMOD, OPTIONS
Allow: 204
Service: MinimalICAP/1.0 "Minimal ICAP Server"
Encapsulated: null-body=0
```

#### RESPMOD
```
RESPMOD icap://YOUR_SERVER_IP:1344/ ICAP/1.0
Host: YOUR_SERVER_IP
User-Agent: GoAnywhere
Allow: 204
Connection: close
preview: 0
Encapsulated: req-hdr=0, res-hdr=55, res-body=98
[HTTP request/response data]
```

**Response:**
```
ICAP/1.0 204 No Content
Date: [Current GMT]
Server: MinimalICAP/1.0
Connection: close
ISTag: "Minimal-001"
Encapsulated: null-body=0
```

## Requirements

- **Python 3.6+**
- **No external dependencies** (uses only standard library)
- **Network access** on port 1344
- **Write permissions** for `saved_files/` directory

## License

This project is provided as-is for testing and educational purposes. Use only in controlled testing environments.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review server logs for detailed error information
3. Verify network connectivity between GoAnywhere and the ICAP server
4. Test with the provided `test_connection.py` utility
