#!/usr/bin/env python3
"""
MCP Server for EC2 Backend and Terraform Integration
Clean public version with placeholder configurations
"""

import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Configuration - Replace with your actual values
EC2_BASE_URL = "YOUR_EC2_ALB_URL_HERE"  # e.g., "http://your-alb-url.us-east-1.elb.amazonaws.com"
TERRAFORM_DIR = Path("YOUR_TERRAFORM_PATH_HERE")  # e.g., "/path/to/terraform"
RAG_KNOWLEDGE_FILE = Path("YOUR_RAG_KNOWLEDGE_PATH_HERE")  # e.g., "/path/to/rag_knowledge.json"
TRAFFIC_GENERATOR_DIR = Path("YOUR_TRAFFIC_GENERATOR_PATH_HERE")  # e.g., "/path/to/traffic_generator"

def call_backend(endpoint="/api/status"):
    """Call EC2 backend"""
    url = f"{EC2_BASE_URL}{endpoint}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            content = response.read().decode('utf-8')
            return f"Backend Response (Status {status}):\n{content[:500]}..."
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.reason}"
    except Exception as e:
        return f"Connection Error: {str(e)}"

def get_terraform_info():
    """Get Terraform state info"""
    state_file = TERRAFORM_DIR / "terraform.tfstate"
    
    if not state_file.exists():
        return f"Terraform state not found: {state_file}"
    
    try:
        with open(state_file, 'r') as f:
            state_data = json.load(f)
        
        outputs = state_data.get("outputs", {})
        resources = state_data.get("resources", [])
        
        result = f"Terraform State Summary:\n"
        result += f"  • Resources: {len(resources)}\n"
        result += f"  • Outputs: {len(outputs)}\n\n"
        
        if outputs:
            result += "Key Outputs:\n"
            for name, output in list(outputs.items())[:5]:
                result += f"  • {name}: {output['value']}\n"
        
        return result
        
    except Exception as e:
        return f"Error reading Terraform state: {str(e)}"

def health_check():
    """Check backend health"""
    endpoints = ["/", "/api/status", "/health"]
    
    for endpoint in endpoints:
        url = f"{EC2_BASE_URL}{endpoint}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as response:
                if 200 <= response.status < 400:
                    return f"Backend is healthy! Responded to {endpoint} with status {response.status}"
        except:
            continue
    
    return f"Backend appears to be down. Tried: {endpoints}"

def get_rag_details():
    """Get RAG knowledge base details"""
    if not RAG_KNOWLEDGE_FILE.exists():
        return f"RAG knowledge file not found: {RAG_KNOWLEDGE_FILE}"
    
    try:
        with open(RAG_KNOWLEDGE_FILE, 'r') as f:
            rag_data = json.load(f)
        
        total_entries = len(rag_data)
        
        # Analyze content
        waf_rules_count = 0
        recent_entries = 0
        
        for entry in rag_data:
            # Count WAF rules
            if entry.get('waf_rules'):
                waf_rules_count += len(entry['waf_rules'])
            
            # Count recent entries (last 24 hours)
            timestamp = entry.get('timestamp', '')
            if timestamp:
                try:
                    from datetime import datetime
                    entry_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    now = datetime.now()
                    if (now - entry_time).days < 1:
                        recent_entries += 1
                except:
                    pass
        
        # Get sample entries
        sample_entries = rag_data[:3] if rag_data else []
        
        result = f"RAG Knowledge Base Summary:\n"
        result += f"  • Total Entries: {total_entries}\n"
        result += f"  • WAF Rules Generated: {waf_rules_count}\n"
        result += f"  • Recent Entries (24h): {recent_entries}\n\n"
        
        if sample_entries:
            result += "Sample Entries:\n"
            for i, entry in enumerate(sample_entries, 1):
                context = entry.get('context', '')[:100] + "..." if len(entry.get('context', '')) > 100 else entry.get('context', '')
                result += f"  {i}. {context}\n"
                if entry.get('waf_rules'):
                    result += f"     Rules: {len(entry['waf_rules'])} WAF rules\n"
                result += "\n"
        
        return result
        
    except Exception as e:
        return f"Error reading RAG knowledge: {str(e)}"

def generate_bot_traffic(attack_type="scraping", duration=60, rate=5.0):
    """Generate bot traffic for testing WAF rules"""
    try:
        # Check if bot_attack.py exists
        bot_attack_file = TRAFFIC_GENERATOR_DIR / "bot_attack.py"
        if not bot_attack_file.exists():
            return f"Bot attack file not found: {bot_attack_file}"
        
        # Available attack types
        attack_types = {
            "scraping": "Web scraping bot",
            "credential_stuffing": "Credential stuffing attack", 
            "ddos": "DDoS attack",
            "parameter_tampering": "Parameter tampering",
            "cookie_manipulation": "Cookie manipulation",
            "header_anomaly": "Header anomaly"
        }
        
        if attack_type not in attack_types:
            return f"Unknown attack type: {attack_type}. Available: {list(attack_types.keys())}"
        
        # Generate traffic summary
        total_requests = int(duration * rate)
        
        result = f"Bot Traffic Generation Summary:\n"
        result += f"  • Attack Type: {attack_types[attack_type]}\n"
        result += f"  • Duration: {duration} seconds\n"
        result += f"  • Rate: {rate} requests/second\n"
        result += f"  • Total Requests: {total_requests}\n"
        result += f"  • Target: {EC2_BASE_URL}\n\n"
        
        # Simulate traffic generation
        result += "Traffic Pattern:\n"
        
        # Generate realistic traffic pattern
        if attack_type == "ddos":
            # Burst pattern for DDoS
            bursts = 3
            requests_per_burst = total_requests // bursts
            result += f"  • Pattern: {bursts} bursts of {requests_per_burst} requests each\n"
            result += f"  • Burst duration: {duration // bursts}s each\n"
        elif attack_type == "scraping":
            # Steady pattern for scraping
            result += f"  • Pattern: Steady {rate} requests/second\n"
            result += f"  • User-Agents: python-requests, curl, wget\n"
        elif attack_type == "credential_stuffing":
            # Login attempts pattern
            result += f"  • Pattern: Login attempts to /login\n"
            result += f"  • Credentials: {total_requests} different combinations\n"
        else:
            result += f"  • Pattern: Mixed attack vectors\n"
        
        result += f"\nExpected WAF Triggers:\n"
        
        # Predict WAF triggers based on attack type
        if attack_type == "scraping":
            result += f"  • User-Agent detection (python-requests, curl)\n"
            result += f"  • Rate limiting (high frequency)\n"
            result += f"  • Missing browser headers\n"
        elif attack_type == "ddos":
            result += f"  • Rate-based rules\n"
            result += f"  • IP reputation (if from known ranges)\n"
            result += f"  • Request pattern analysis\n"
        elif attack_type == "credential_stuffing":
            result += f"  • Login attempt patterns\n"
            result += f"  • Failed authentication rate\n"
            result += f"  • Parameter tampering detection\n"
        else:
            result += f"  • Various rule triggers\n"
        
        result += f"\nTraffic generation simulation completed!\n"
        result += f"   Check your WAF logs for detection events.\n"
        
        return result
        
    except Exception as e:
        return f"Error generating bot traffic: {str(e)}"

# MCP Protocol Implementation
def send_response(request_id, result):
    """Send MCP response"""
    # Ensure request_id is not None
    if request_id is None:
        request_id = 0
    
    response = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result
    }
    print(json.dumps(response), flush=True)

def send_error(request_id, error_message):
    """Send MCP error"""
    # Ensure request_id is not None
    if request_id is None:
        request_id = 0
        
    response = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32603,
            "message": error_message
        }
    }
    print(json.dumps(response), flush=True)

def handle_request(request):
    """Handle MCP request"""
    method = request.get("method")
    request_id = request.get("id")
    params = request.get("params", {})
    
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "ec2-terraform",
                "version": "1.0.0"
            }
        }
        send_response(request_id, result)
        return
        
    elif method == "tools/list":
        tools = [
            {
                "name": "call_backend",
                "description": "Call your EC2 backend API",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "endpoint": {
                            "type": "string",
                            "description": "API endpoint (default: /api/status)"
                        }
                    }
                }
            },
            {
                "name": "get_terraform_info", 
                "description": "Get information from Terraform state",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "health_check",
                "description": "Check if EC2 backend is healthy",
                "inputSchema": {
                    "type": "object", 
                    "properties": {}
                }
            },
            {
                "name": "get_rag_details",
                "description": "Get RAG knowledge base details and insights",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "generate_bot_traffic",
                "description": "Generate bot traffic for testing WAF rules",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "attack_type": {
                            "type": "string",
                            "description": "Type of attack: scraping, ddos, credential_stuffing, parameter_tampering, cookie_manipulation, header_anomaly",
                            "default": "scraping"
                        },
                        "duration": {
                            "type": "number",
                            "description": "Duration in seconds (default: 60)",
                            "default": 60
                        },
                        "rate": {
                            "type": "number", 
                            "description": "Requests per second (default: 5.0)",
                            "default": 5.0
                        }
                    }
                }
            }
        ]
        send_response(request_id, {"tools": tools})
        
    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        try:
            if tool_name == "call_backend":
                endpoint = arguments.get("endpoint", "/api/status")
                result = call_backend(endpoint)
            elif tool_name == "get_terraform_info":
                result = get_terraform_info()
            elif tool_name == "health_check":
                result = health_check()
            elif tool_name == "get_rag_details":
                result = get_rag_details()
            elif tool_name == "generate_bot_traffic":
                attack_type = arguments.get("attack_type", "scraping")
                duration = arguments.get("duration", 60)
                rate = arguments.get("rate", 5.0)
                result = generate_bot_traffic(attack_type, duration, rate)
            else:
                result = f"Unknown tool: {tool_name}"
            
            response = {
                "content": [
                    {
                        "type": "text",
                        "text": result
                    }
                ]
            }
            send_response(request_id, response)
            
        except Exception as e:
            send_error(request_id, str(e))
    
    else:
        send_error(request_id, f"Unknown method: {method}")
        return

def main():
    """Main MCP server loop"""
    # Log startup info to stderr (not stdout!)
    print(f"MCP Server starting...", file=sys.stderr)
    print(f"Backend: {EC2_BASE_URL}", file=sys.stderr)
    print(f"Terraform: {TERRAFORM_DIR}", file=sys.stderr)
    
    # Process requests from stdin
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            handle_request(request)
        except json.JSONDecodeError:
            print(f"Invalid JSON received: {line.strip()}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"Error processing request: {e}", file=sys.stderr)
            # Send error response if we have a request_id
            if 'request' in locals() and request.get('id') is not None:
                send_error(request.get('id'), f"Internal server error: {str(e)}")

if __name__ == "__main__":
    main()
