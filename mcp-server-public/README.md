# MCP Server for EC2 Backend and Terraform Integration

A Model Context Protocol (MCP) server that provides tools for interacting with EC2 backends, Terraform infrastructure, RAG knowledge bases, and bot traffic generation.

## Features

This MCP server provides 5 powerful tools:

1. **`call_backend`** - Call your EC2 backend API endpoints
2. **`get_terraform_info`** - Get information from Terraform state files
3. **`health_check`** - Check if your EC2 backend is healthy
4. **`get_rag_details`** - Get RAG knowledge base details and insights
5. **`generate_bot_traffic`** - Generate bot traffic for testing WAF rules

## Prerequisites

- Python 3.7+
- Claude Desktop (for MCP client)
- Access to your EC2 backend
- Terraform state files
- RAG knowledge base files
- Traffic generator scripts

## Setup

### 1. Clone and Configure

```bash
git clone <your-repo>
cd mcp-server-public
```

### 2. Update Configuration

Edit `src/mcp_server.py` and replace the placeholder values:

```python
# Configuration - Replace with your actual values
EC2_BASE_URL = "YOUR_EC2_ALB_URL_HERE"  # e.g., "http://your-alb-url.us-east-1.elb.amazonaws.com"
TERRAFORM_DIR = Path("YOUR_TERRAFORM_PATH_HERE")  # e.g., "/path/to/terraform"
RAG_KNOWLEDGE_FILE = Path("YOUR_RAG_KNOWLEDGE_PATH_HERE")  # e.g., "/path/to/rag_knowledge.json"
TRAFFIC_GENERATOR_DIR = Path("YOUR_TRAFFIC_GENERATOR_PATH_HERE")  # e.g., "/path/to/traffic_generator"
```

### 3. Configure Claude Desktop

Create or update your Claude Desktop configuration file:

**Windows:**
```
C:\Users\<username>\AppData\Roaming\Claude\claude_desktop_config.json
```

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

Add this configuration:

```json
{
  "mcpServers": {
    "ec2-terraform": {
      "command": "python",
      "args": ["/path/to/mcp-server-public/src/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/path/to/mcp-server-public"
      }
    }
  }
}
```

### 4. Restart Claude Desktop

Completely close and restart Claude Desktop to pick up the new MCP server.

## Usage

Once configured, you can use these commands in Claude Desktop:

### Backend Operations
- **"Call my backend API"**
- **"Check if my backend is healthy"**
- **"Call backend endpoint /api/status"**

### Terraform Operations
- **"Show me my Terraform infrastructure info"**
- **"Get Terraform state details"**

### RAG Operations
- **"Show me my RAG knowledge base details"**
- **"What's in my RAG system?"**

### Bot Traffic Generation
- **"Generate scraping bot traffic for 30 seconds"**
- **"Create a DDoS attack simulation"**
- **"Generate credential stuffing traffic"**

## Available Tools

### 1. call_backend
Calls your EC2 backend API endpoints.

**Parameters:**
- `endpoint` (string, optional): API endpoint (default: `/api/status`)

### 2. get_terraform_info
Retrieves information from your Terraform state file.

**Parameters:** None

### 3. health_check
Checks if your EC2 backend is responding to health endpoints.

**Parameters:** None

### 4. get_rag_details
Provides insights into your RAG knowledge base.

**Parameters:** None

### 5. generate_bot_traffic
Generates bot traffic for testing WAF rules.

**Parameters:**
- `attack_type` (string, optional): Type of attack - `scraping`, `ddos`, `credential_stuffing`, `parameter_tampering`, `cookie_manipulation`, `header_anomaly` (default: `scraping`)
- `duration` (number, optional): Duration in seconds (default: 60)
- `rate` (number, optional): Requests per second (default: 5.0)

## Testing

Test the server manually:

```bash
cd mcp-server-public
python src/mcp_server.py
```

Then send JSON-RPC requests via stdin:

```json
{"jsonrpc": "2.0", "id": 1, "method": "initialize"}
{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "health_check", "arguments": {}}}
```

## Security Notes

- Never commit sensitive URLs, paths, or credentials
- Use environment variables for sensitive configuration
- Keep your Terraform state files secure
- Monitor your WAF logs when generating bot traffic

## Troubleshooting

### Server Not Appearing in Claude Desktop
1. Check the configuration file path
2. Verify the Python path is correct
3. Restart Claude Desktop completely
4. Check Claude Desktop logs

### Connection Errors
1. Verify your EC2 backend is running
2. Check firewall and security group settings
3. Ensure the ALB URL is correct

### File Not Found Errors
1. Update the file paths in the configuration
2. Ensure files exist at the specified locations
3. Check file permissions

## Project Structure

```
mcp-server-public/
 src/
    mcp_server.py          # Main MCP server
 requirements.txt           # Dependencies
 README.md                  # This file
 SETUP.md                   # Quick setup guide
 .gitignore                 # Git ignore rules
 COMMIT_CHECKLIST.md        # Security checklist
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Model Context Protocol (MCP) specification
- Claude Desktop for MCP client support
- AWS WAF and Terraform communities

---

## Security Notice

