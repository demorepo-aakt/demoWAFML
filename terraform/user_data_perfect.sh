#!/bin/bash
set -e  # Exit on any error

# Logging setup
exec > >(tee /var/log/user-data.log) 2>&1
echo "=== Bot Detection Demo EC2 Setup Started at $(date) ==="

# Update system
yum update -y
yum install -y python3 python3-pip curl

# Install Flask and dependencies
pip3 install flask==2.3.3 requests

# Create application directory
mkdir -p /opt/bot-detection
cd /opt/bot-detection

# Create robust Flask backend
cat > /opt/bot-detection/app.py << 'EOF'
#!/usr/bin/env python3
from flask import Flask, jsonify, request
import json
import logging
from datetime import datetime
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route('/health')
def health():
    """Health check endpoint - returns immediately"""
    return jsonify({
        'status': 'healthy', 
        'server': 'aws-ec2-backend',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Handle all requests with proper logging"""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    
    logger.info(f"Request: {request.method} /{path} from {client_ip}")
    
    response_data = {
        'status': 'success',
        'message': f'Bot Detection Demo Backend - Path: /{path}',
        'method': request.method,
        'timestamp': datetime.now().isoformat(),
        'server': 'aws-ec2-backend',
        'client_ip': client_ip,
        'path': path
    }
    
    # Simulate bot detection logic
    is_suspicious = False
    if user_agent and ('bot' in user_agent.lower() or 'crawler' in user_agent.lower()):
        is_suspicious = True
        logger.warning(f"Suspicious request detected from {client_ip}: {user_agent}")
        return jsonify({
            'error': 'Request blocked - Suspicious bot behavior detected',
            'blocked_reason': 'Bot user agent detected'
        }), 418  # I'm a teapot - custom WAF response
    
    return jsonify(response_data), 200

@app.route('/api/data')
def api_data():
    """API data endpoint"""
    return jsonify({
        'data': [
            {'id': 1, 'value': 'sample_data', 'type': 'legitimate'},
            {'id': 2, 'value': 'demo_content', 'type': 'user_generated'}
        ],
        'timestamp': datetime.now().isoformat(),
        'server': 'aws-backend'
    }), 200

if __name__ == '__main__':
    logger.info("Starting Bot Detection Demo Backend on port 80...")
    app.run(host='0.0.0.0', port=80, debug=False, threaded=True)
EOF

# Make app executable
chmod +x /opt/bot-detection/app.py

# Create systemd service with proper dependencies and health checks
cat > /etc/systemd/system/bot-detection.service << 'EOF'
[Unit]
Description=Bot Detection Demo Flask Backend
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/bot-detection
Environment=PYTHONPATH=/opt/bot-detection
Environment=FLASK_ENV=production
ExecStartPre=/bin/sleep 10
ExecStart=/usr/bin/python3 /opt/bot-detection/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
TimeoutStartSec=120

# Health check
ExecStartPost=/bin/bash -c 'for i in {1..30}; do curl -f http://localhost:80/health && break || sleep 2; done'

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable bot-detection.service

# Start the service and verify it's working
echo "Starting bot-detection service..."
systemctl start bot-detection.service

# Wait for service to be ready
sleep 20

# Verify service is running
if systemctl is-active --quiet bot-detection.service; then
    echo "Bot Detection service is running"
else
    echo "Bot Detection service failed to start"
    systemctl status bot-detection.service
    journalctl -u bot-detection.service --no-pager
    exit 1
fi

# Test health endpoint
echo "Testing health endpoint..."
for i in {1..10}; do
    if curl -f http://localhost:80/health; then
        echo "Health check passed"
        break
    else
        echo "Waiting for health check... (attempt $i/10)"
        sleep 3
    fi
done

# Final verification
curl -f http://localhost:80/health || {
    echo "Final health check failed"
    exit 1
}

echo "Bot Detection Demo Backend setup completed successfully at $(date)"
echo "Backend is ready to serve traffic on port 80"





