# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a production-ready MCP (Model Context Protocol) server running in a Kali Linux Docker container. It provides AI assistants with access to a comprehensive security toolset for penetration testing and security analysis. The server communicates via Server-Sent Events (SSE) and allows AI to execute commands in a controlled environment.

## Commands

### Building and Running

```bash
# Build the Docker image
docker build -t kali-mcp-server .

# Run with default settings (SSE mode on port 8000)
docker run --privileged -p 8000:8000 kali-mcp-server

# Run the tests
./run_tests.sh

# Quick build and run
./run_docker.sh
```

### Development Commands

```bash
# Install development dependencies
pip install -e ".[dev]"

# Type checking
pyright

# Linting
ruff check .

# Formatting
ruff format .

# Running tests
pytest
```

### Package Management

```bash
# Install dependencies
pip install -r requirements.txt

# Add a new dependency
pip install <package-name>
```

## Architecture

The project uses **FastMCP** for the MCP server. Layout:

1. **`kali_mcp_server/server.py`** – FastMCP app: creates `FastMCP(name="kali-mcp-server")`, registers all tools with `mcp.add_tool(...)`, and runs with `mcp.run(transport=..., port=...)`. Supports transports: `stdio`, `sse`, `http`.
2. **`kali_mcp_server/tools.py`** – Tool implementations; each tool is an async function that returns a `str` (FastMCP sends it as the tool result). Includes task lifecycle (`task_list`, `task_logs`, `task_stop`), sessions, scans, and helpers.
3. **Entry points** – `main.py` and `kali_mcp_server/__main__.py` call the Click `main()` in server (e.g. `--transport sse --port 8000`).

Tools include: `run`, `fetch`, `resources`, `task_list`, `task_logs`, `task_stop`, session tools, and scan tools (`vulnerability_scan`, `web_audit`, `msf_exploit`, `nmap_nse_scan`, etc.).

Commands are validated against an allowlist for security, and long-running commands are executed in the background.

The Docker container is based on Kali Linux and includes a wide range of pre-installed security tools:
- Network scanning (nmap)
- Penetration testing (metasploit)
- Password brute-forcing (hydra)
- Directory enumeration (gobuster, dirb)
- Web vulnerability scanning (nikto)
- SQL injection testing (sqlmap)

The container runs as root so that nmap and other tools can use raw sockets (e.g. SYN scan, OS detection).

## Integration with Claude Desktop

The MCP server is designed to be used with Claude Desktop by adding a configuration entry to:
`~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "transport": "sse",
      "url": "http://localhost:8000/sse",
      "command": "docker run --privileged -p 8000:8000 kali-mcp-server"
    }
  }
}
```

See CLAUDE_INTEGRATION.md for detailed integration instructions.

## Security Note

This container provides access to powerful security tools. It includes several security measures:

1. Commands are validated against an allowlist
2. The server runs as root inside the container so scanning tools (nmap, ping, etc.) have required capabilities
3. Long-running commands are executed with appropriate controls
4. Input validation is applied to commands and URLs

It should only be used responsibly and in controlled environments.