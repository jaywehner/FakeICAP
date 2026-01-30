# Deployment Guide

## Quick Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd FakeICAP
   ```

2. **Configure server IP:**
   ```bash
   cp config.example.py config.py
   # Edit config.py and replace YOUR_SERVER_IP with your actual IP
   ```

3. **Start the server:**
   ```bash
   python minimal_icap.py
   ```

## Configuration

### Server IP Configuration

**Option 1: Edit the code directly**
- Edit `minimal_icap.py` line 244:
  ```python
  host = 'YOUR_SERVER_IP'  # Replace with your actual server IP
  ```

**Option 2: Use environment variable**
```bash
export ICAP_SERVER_IP="192.168.1.100"
python minimal_icap.py
```

**Option 3: Create config.py**
```bash
cp config.example.py config.py
# Edit config.py with your settings
```

### Network Requirements

- **Port 1344** must be open on the server
- **Firewall rules** to allow GoAnywhere to connect
- **Network connectivity** between GoAnywhere and ICAP server

### File Storage

Files are organized by date:
```
saved_files/
├── 2026/
│   ├── 01/
│   │   ├── 29/
│   │   │   ├── {GUID}_filename.ext
│   │   │   └── record_{GUID}.txt
```

## Security Considerations

- **Network isolation**: Run in isolated network segment
- **Access control**: Limit access to GoAnywhere servers only
- **File permissions**: Restrict access to saved_files directory
- **Regular cleanup**: Implement log rotation and file cleanup

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/fakeicap.service`:
```ini
[Unit]
Description=FakeICAP Server
After=network.target

[Service]
Type=simple
User=icap
WorkingDirectory=/opt/fakeicap
ExecStart=/usr/bin/python3 /opt/fakeicap/minimal_icap.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable fakeicap
sudo systemctl start fakeicap
```

### Docker Deployment

Create `Dockerfile`:
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . .

RUN mkdir -p saved_files
EXPOSE 1344

CMD ["python", "minimal_icap.py"]
```

Build and run:
```bash
docker build -t fakeicap .
docker run -d -p 1344:1344 -v $(pwd)/saved_files:/app/saved_files fakeicap
```

### Monitoring

Monitor the service with:
```bash
# Check logs
tail -f saved_files/*.log

# Check process
ps aux | grep minimal_icap

# Check port
netstat -tlnp | grep 1344
```

## Troubleshooting

### Common Issues

1. **Port already in use:**
   ```bash
   sudo lsof -i :1344
   sudo kill -9 <PID>
   ```

2. **Permission denied:**
   ```bash
   sudo chown -R $USER:$USER saved_files/
   chmod 755 saved_files/
   ```

3. **Connection refused:**
   - Check firewall settings
   - Verify IP address configuration
   - Test with telnet: `telnet <server-ip> 1344`

### Log Analysis

Monitor for:
- Connection patterns
- File processing errors
- Network timeouts
- Storage space issues
