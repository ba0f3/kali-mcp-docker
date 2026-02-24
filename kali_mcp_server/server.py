"""
MCP Server implementation for Kali Linux security tools using FastMCP.

This module provides the main server functionality for the Kali MCP Server,
including tool registration and transport configuration (stdio, SSE, HTTP).
"""

import sys

import click
from fastmcp import FastMCP

from kali_mcp_server.tools import (
    create_report,
    download_file,
    exploit_search,
    fetch_website,
    file_analysis,
    form_analysis,
    header_analysis,
    list_system_resources,
    msf_exploit,
    network_discovery,
    nmap_nse_scan,
    run_command,
    save_output,
    session_create,
    session_delete,
    session_history,
    session_list,
    session_status,
    session_switch,
    spider_website,
    ssl_analysis,
    subdomain_enum,
    task_list,
    task_logs,
    task_stop,
    vulnerability_scan,
    web_audit,
    web_enumeration,
)

# Ensure sessions directory exists on import (tools use it)
from kali_mcp_server.tools import ensure_sessions_dir

ensure_sessions_dir()

MCP_INSTRUCTIONS = """
This server provides security and penetration testing tools in a Kali Linux environment.
- Use run(command) for shell commands; long-running commands (nmap, nikto, etc.) run in background and return task_id.
- Use task_list to see background tasks, task_logs(task_id) to read output. Do not use download_file for server log files.
- Use session_create/session_switch to organize work; scan outputs are stored per session.
- For scans (vulnerability_scan, web_audit, msf_exploit, etc.) call task_logs(task_id) to get results.
"""

mcp = FastMCP(
    name="kali-mcp-server",
    instructions=MCP_INSTRUCTIONS.strip(),
)

# --- Register all tools (FastMCP infers name and schema from function signature and docstring) ---
mcp.add_tool(fetch_website)
mcp.add_tool(run_command)
mcp.add_tool(task_list)
mcp.add_tool(task_logs)
mcp.add_tool(task_stop)
mcp.add_tool(list_system_resources)
mcp.add_tool(vulnerability_scan)
mcp.add_tool(web_enumeration)
mcp.add_tool(network_discovery)
mcp.add_tool(exploit_search)
mcp.add_tool(save_output)
mcp.add_tool(create_report)
mcp.add_tool(file_analysis)
mcp.add_tool(download_file)
mcp.add_tool(session_create)
mcp.add_tool(session_list)
mcp.add_tool(session_switch)
mcp.add_tool(session_status)
mcp.add_tool(session_delete)
mcp.add_tool(session_history)
mcp.add_tool(spider_website)
mcp.add_tool(form_analysis)
mcp.add_tool(header_analysis)
mcp.add_tool(ssl_analysis)
mcp.add_tool(subdomain_enum)
mcp.add_tool(web_audit)
mcp.add_tool(msf_exploit)
mcp.add_tool(nmap_nse_scan)


@click.command()
@click.option("--port", default=8000, help="Port to listen on for HTTP/SSE connections")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "http"]),
    default="http",
    help="Transport: stdio (local), sse (legacy HTTP), http (Streamable HTTP)",
)
@click.option("--host", default="0.0.0.0", help="Host to bind to (for sse/http)")
@click.option("--debug", is_flag=True, default=False, help="Enable debug mode")
def main(port: int, transport: str, host: str, debug: bool) -> int:
    """
    Start the Kali MCP Server with the specified transport.
    """
    if transport == "stdio":
        print("Starting Kali MCP Server (stdio transport)", file=sys.stderr)
        mcp.run()
        return 0
    # SSE or HTTP: run with host and port
    print(f"Starting Kali MCP Server on {host}:{port} (transport={transport})", file=sys.stderr)
    if transport == "sse":
        print(f"  SSE (legacy): http://localhost:{port}/sse", file=sys.stderr)
    else:
        print(f"  Streamable HTTP: http://localhost:{port}/mcp", file=sys.stderr)
    mcp.run(transport=transport, host=host, port=port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
