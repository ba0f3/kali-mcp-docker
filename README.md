# 🛡️ Kali MCP Server

A production-ready MCP (Model Context Protocol) server running in a Kali Linux Docker container, providing AI assistants with access to a comprehensive security toolset.

[![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)](https://www.kali.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

## 📋 Overview

This project provides a Docker containerized MCP server that runs on Kali Linux, giving AI assistants (like Claude) access to a full suite of security and penetration testing tools. The server communicates via Server-Sent Events (SSE) and allows AI to execute commands in a controlled environment with appropriate security measures.

## ✨ Features

- **🔒 Security Tools Access**: Full access to Kali Linux security toolset through a controlled interface
- **🛡️ Command Validation**: Commands are validated against an allowlist for security
- **🌐 Web Content Fetching**: Retrieve and analyze web content
- **📊 Resource Information**: Comprehensive system resource details and command examples
- **👤 Security Focus**: Command validation and allowlist; container runs as root so nmap/ping etc. have required capabilities

### 🔧 Pre-installed Security Tools

- **🔍 Network Scanning**: nmap, netcat
- **🕸️ Web Application Testing**: nikto, gobuster, dirb
- **🧪 Penetration Testing**: metasploit-framework
- **🔑 Credential Testing**: hydra
- **💉 Data Extraction**: sqlmap
- **ℹ️ Information Gathering**: whois, dig, host

## 🚀 Quick Start

### 🐳 Building and Running the Container

```bash
# Quick start with the helper script
./run_docker.sh

# Or manually:
# Build the Docker image
docker build -t kali-mcp-server .

# Run with default settings (SSE mode on port 8000)
docker run -p 8000:8000 kali-mcp-server
```

### 🔌 Connecting to Claude Desktop

1. Edit your Claude Desktop config file:
   - Location: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Add this configuration:
     ```json
     {
       "mcpServers": {
         "kali-mcp-server": {
           "transport": "sse",
           "url": "http://localhost:8000/sse",
           "command": "docker run -p 8000:8000 kali-mcp-server"
         }
       }
     }
     ```

2. Restart Claude Desktop
3. Test the connection with a simple command:
   ```
   /run nmap -F localhost
   ```

## 🛠️ Available MCP Tools

The server provides several tools through the MCP protocol:

### 💻 `run` - Execute Commands

Run security tools and commands in the Kali Linux environment.

```
/run nmap -F localhost
```

Commands are validated against an allowlist for security. Long-running commands will be executed in the background with results saved to an output file.

### 🌐 `fetch` - Retrieve Web Content

Fetch and analyze web content from specified URLs.

```
/fetch https://example.com
```

### 📈 `resources` - List Available Resources

Get information about the system and available commands. (The AI can use these resources to run the commands on you behalf using Natural Language.)

```
/resources
```

### 🚀 `vulnerability_scan` - Automated Vulnerability Assessment

Perform automated vulnerability assessment with multiple tools.

```
/vulnerability_scan target=127.0.0.1 scan_type=quick
/vulnerability_scan target=example.com scan_type=comprehensive
```

**Scan Types:**
- `quick`: Fast scan with nmap and nikto
- `comprehensive`: Full scan with multiple tools
- `web`: Web-focused vulnerability assessment
- `network`: Network-focused vulnerability assessment

### 🌐 `web_enumeration` - Web Application Discovery

Perform comprehensive web application discovery and enumeration.

```
/web_enumeration target=http://example.com enumeration_type=full
/web_enumeration target=example.com enumeration_type=aggressive
```

**Enumeration Types:**
- `basic`: Basic web enumeration with nikto and gobuster
- `full`: Comprehensive enumeration including vhost discovery
- `aggressive`: Aggressive enumeration with SQL injection testing

### 🔍 `network_discovery` - Network Reconnaissance

Perform multi-stage network reconnaissance and discovery.

```
/network_discovery target=192.168.1.0/24 discovery_type=comprehensive
/network_discovery target=example.com discovery_type=stealth
```

**Discovery Types:**
- `quick`: Quick network discovery
- `comprehensive`: Comprehensive network mapping
- `stealth`: Stealthy network reconnaissance

### 🔍 `exploit_search` - Exploit Database Search

Search for exploits using searchsploit and other exploit databases.

```
/exploit_search search_term=apache search_type=web
/exploit_search search_term=CVE-2021-44228 search_type=all
```

**Search Types:**
- `all`: Search all exploit types
- `web`: Web application exploits
- `remote`: Remote exploits
- `local`: Local exploits
- `dos`: Denial of service exploits

### 💾 `save_output` - Save Content to File

Save content to a timestamped file for evidence collection.

```
/save_output content="Scan results here" filename=my_scan category=scan
/save_output content="Enumeration data" category=enum
```

**Categories:**
- `general`: General content (default)
- `scan`: Vulnerability scan results
- `enum`: Enumeration results
- `evidence`: Evidence collection

### 📋 `create_report` - Generate Structured Reports

Generate a structured report from findings.

```
/create_report title="Security Assessment Report" findings="Vulnerabilities found..." report_type=markdown
/create_report title="Network Scan Results" findings="Open ports..." report_type=json
```

**Report Types:**
- `markdown`: Markdown format (default)
- `text`: Plain text format
- `json`: JSON format

### 🔍 `file_analysis` - Analyze Files

Analyze a file using various tools (file type, strings, hash).

```
/file_analysis filepath=./suspicious_file
/file_analysis filepath=/path/to/downloaded/file
```

**Analysis includes:**
- File type detection
- String extraction
- SHA256 hash
- File metadata
- Content preview

### 📥 `download_file` - Download Files

Download a file from a URL and save it locally.

```
/download_file url=https://example.com/file.txt filename=downloaded_file
/download_file url=https://example.com/script.sh
```

**Features:**
- Automatic filename extraction from URL
- SHA256 hash generation
- Content-type detection
- Safe filename sanitization

### 🗂️ `session_create` - Create New Session

Create a new pentest session with name, description, and target.

```
/session_create session_name="web_app_test" description="Web application security assessment" target="example.com"
/session_create session_name="network_scan" target="192.168.1.0/24"
```

**Features:**
- Session metadata storage
- Automatic session activation
- Organized file structure

### 📋 `session_list` - List Sessions

List all pentest sessions with metadata and status.

```
/session_list
```

**Shows:**
- All available sessions
- Active session indicator
- Session descriptions and targets
- Creation dates and history counts

### 🔄 `session_switch` - Switch Sessions

Switch to a different pentest session.

```
/session_switch session_name="web_app_test"
```

**Features:**
- Validates session existence
- Updates active session
- Shows session details after switch

### 📊 `session_status` - Session Status

Show current session status and summary.

```
/session_status
```

**Shows:**
- Active session details
- Session metadata
- File count and history
- Recent activity

### 🗑️ `session_delete` - Delete Session

Delete a pentest session and all its evidence.

```
/session_delete session_name="old_session"
```

**Safety Features:**
- Cannot delete active session
- Confirms deletion with session details
- Removes all session files and evidence

### 📜 `session_history` - Session History

Show command/evidence history for the current session.

```
/session_history
```

**Shows:**
- Chronological history of activities
- Action types and timestamps
- Session-specific evidence tracking

## Enhanced Web Application Testing Tools

### 🕷️ Spider Website
Comprehensive web crawling and spidering using gospider.

```bash
/spider_website url=https://example.com depth=2 threads=10
```

**Parameters:**
- `url` (required): Target URL to spider
- `depth` (optional): Crawling depth (default: 2)
- `threads` (optional): Number of concurrent threads (default: 10)

### 📝 Form Analysis
Discover and analyze web forms for security testing.

```bash
/form_analysis url=https://example.com scan_type=comprehensive
```

**Parameters:**
- `url` (required): Target URL to analyze
- `scan_type` (optional): Type of analysis - "basic", "comprehensive", "aggressive" (default: "comprehensive")

### 📋 Header Analysis
Analyze HTTP headers for security information and misconfigurations.

```bash
/header_analysis url=https://example.com include_security=true
```

**Parameters:**
- `url` (required): Target URL to analyze
- `include_security` (optional): Include security header analysis (default: true)

### 🔐 SSL Analysis
Perform SSL/TLS security assessment using testssl.sh.

```bash
/ssl_analysis url=example.com port=443
```

**Parameters:**
- `url` (required): Target URL to analyze
- `port` (optional): SSL port (default: 443)

### 🔍 Subdomain Enumeration
Perform subdomain enumeration using multiple tools (subfinder, amass, waybackurls).

```bash
/subdomain_enum url=example.com enum_type=comprehensive
```

**Parameters:**
- `url` (required): Target domain to enumerate
- `enum_type` (optional): Type of enumeration - "basic", "comprehensive", "aggressive" (default: "comprehensive")

### 🔍 Web Audit
Perform comprehensive web application security audit.

```bash
/web_audit url=https://example.com audit_type=comprehensive
```

**Parameters:**
- `url` (required): Target URL to audit
- `audit_type` (optional): Type of audit - "basic", "comprehensive", "aggressive" (default: "comprehensive")

**Tools Used in Web Audit:**
- Nikto (web vulnerability scanner)
- Gobuster (directory/vhost enumeration)
- SQLMap (SQL injection testing)
- Dirb (directory enumeration)
- TestSSL.sh (SSL/TLS analysis)
- Curl (header analysis)

## Session Management Tools

## ⚠️ Troubleshooting

### 🔌 Connection Issues

- Ensure port 8000 is available on your machine
- Check that the Docker container is running: `docker ps`
- Verify the URL in Claude Desktop configuration matches the container's port

### ⚙️ Command Execution Problems

- If commands timeout, try running them in the background: `command > output.txt &`
- Use `/resources` to see examples of properly formatted commands
- For permission errors, ensure you're not trying to access protected system areas

## 🔒 Security Considerations

This container provides access to powerful security tools. Please observe the following:

- Use responsibly and only in controlled environments
- The container is designed to be run locally and should not be exposed to the internet
- Commands are validated against an allowlist for security
- The server runs as root inside the container so scanning tools (nmap, ping, traceroute) work with raw sockets
- Only use this tool for legitimate security testing with proper authorization

## 📋 Requirements

- Docker
- Claude Desktop or other SSE enabled MCP clients
- Port 8000 available on your host machine

## 👨‍💻 Development

### 🛠️ Setting Up a Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/kali-mcp-server.git
cd kali-mcp-server

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -e ".[dev]"
```

### 🧪 Running Tests

```bash
# Run tests with the helper script
./run_tests.sh

# Or manually:
# Run all tests
pytest

# Run with coverage
pytest --cov=kali_mcp_server
```


## 🙏 Acknowledgements

- Kali Linux for their security-focused distribution
- Anthropic for Claude and the MCP protocol
- The open-source security tools community

---

<p align="center">
  <sub>Built for security professionals and AI assistants</sub>
</p>
