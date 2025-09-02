# MCP Server Setup Guide

## Quick Start

### 1. Download the Code
```bash
git clone <your-repo>
cd mcp-server-public
```

### 2. Configure Your Environment
Edit `src/mcp_server.py` and update these lines with your actual values:

```python
# Replace these placeholder values with your actual configuration
EC2_BASE_URL = "http://your-alb-url.us-east-1.elb.amazonaws.com"
TERRAFORM_DIR = Path("/path/to/your/terraform")
RAG_KNOWLEDGE_FILE = Path("/path/to/your/rag_knowledge.json")
TRAFFIC_GENERATOR_DIR = Path("/path/to/your/traffic_generator")
```

### 3. Configure Claude Desktop

**Find your Claude Desktop config file:**

**Windows:**
```
C:\Users\<your-username>\AppData\Roaming\Claude\claude_desktop_config.json
```

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

**Add this configuration:**
```json
{
  "mcpServers": {
    "ec2-terraform": {
      "command": "python",
      "args": ["/full/path/to/mcp-server-public/src/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/full/path/to/mcp-server-public"
      }
    }
  }
}
```

### 4. Restart Claude Desktop
- Completely close Claude Desktop
- Start it again
- Look for the tools icon in the chat interface

## Test Your Setup

Try these commands in Claude Desktop:

1. **"Check if my backend is healthy"**
2. **"Show me my Terraform infrastructure info"**
3. **"Generate scraping bot traffic for 30 seconds"**

## Troubleshooting

### Server Not Appearing
- Check the config file path
- Verify Python path is correct
- Restart Claude Desktop completely
- Check Claude Desktop logs

### Connection Errors
- Verify your EC2 backend is running
- Check firewall settings
- Ensure ALB URL is correct

### File Not Found
- Update file paths in configuration
- Ensure files exist at specified locations
- Check file permissions

## Need Help?

If you encounter issues:
1. Check the troubleshooting section
2. Verify all paths are correct
3. Ensure Claude Desktop is restarted
4. Check that your backend is accessible
