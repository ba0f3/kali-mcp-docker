"""
MCP Server implementation for Kali Linux security tools.

This module provides the main server functionality for the Kali MCP Server,
including tool registration, transport configuration, and server initialization.
"""

from typing import Any, Dict, List, Sequence, Union

import anyio
import click
import mcp.types as types
from mcp.server.lowlevel import Server

from kali_mcp_server.tools import (
    fetch_website, 
    list_system_resources, 
    run_command,
    vulnerability_scan,
    web_enumeration,
    network_discovery,
    exploit_search,
    save_output,
    create_report,
    file_analysis,
    download_file,
    session_create,
    session_list,
    session_switch,
    session_status,
    session_delete,
    session_history,
    spider_website,
    form_analysis,
    header_analysis,
    ssl_analysis,
    subdomain_enum,
    web_audit,
    msf_exploit,
    nmap_nse_scan,
    task_list,
    task_stop,
    task_logs
)

# Create server instance with descriptive name
kali_server = Server("kali-mcp-server")


@kali_server.call_tool()
async def handle_tool_request(
    name: str, arguments: Dict[str, Any]
) -> Sequence[Union[types.TextContent, types.ImageContent, types.EmbeddedResource]]:
    """
    Handle MCP tool requests by routing to the appropriate handler.
    
    Args:
        name: The name of the tool being called
        arguments: Dictionary of arguments for the tool
        
    Returns:
        Sequence of content items returned by the tool
        
    Raises:
        ValueError: If the tool name is unknown or required arguments are missing
    """
    if name == "fetch":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        return await fetch_website(arguments["url"])
    
    elif name == "run":
        if "command" not in arguments:
            raise ValueError("Missing required argument 'command'")
        return await run_command(arguments["command"])
    
    elif name == "resources":
        return await list_system_resources()
    
    elif name == "vulnerability_scan":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        scan_type = arguments.get("scan_type", "comprehensive")
        return await vulnerability_scan(arguments["target"], scan_type)
    
    elif name == "web_enumeration":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        enum_type = arguments.get("enumeration_type", "full")
        return await web_enumeration(arguments["target"], enum_type)
    
    elif name == "network_discovery":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        discovery_type = arguments.get("discovery_type", "comprehensive")
        return await network_discovery(arguments["target"], discovery_type)
    
    elif name == "exploit_search":
        if "search_term" not in arguments:
            raise ValueError("Missing required argument 'search_term'")
        search_type = arguments.get("search_type", "all")
        return await exploit_search(arguments["search_term"], search_type)
    
    elif name == "save_output":
        if "content" not in arguments:
            raise ValueError("Missing required argument 'content'")
        filename = arguments.get("filename")
        category = arguments.get("category", "general")
        return await save_output(arguments["content"], filename if filename else None, category)
    
    elif name == "create_report":
        if "title" not in arguments:
            raise ValueError("Missing required argument 'title'")
        if "findings" not in arguments:
            raise ValueError("Missing required argument 'findings'")
        report_type = arguments.get("report_type", "markdown")
        return await create_report(arguments["title"], arguments["findings"], report_type)
    
    elif name == "file_analysis":
        if "filepath" not in arguments:
            raise ValueError("Missing required argument 'filepath'")
        return await file_analysis(arguments["filepath"])
    
    elif name == "download_file":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        filename = arguments.get("filename")
        return await download_file(arguments["url"], filename if filename else None)
    
    elif name == "session_create":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        description = arguments.get("description", "")
        target = arguments.get("target", "")
        return await session_create(arguments["session_name"], description, target)
    
    elif name == "session_list":
        return await session_list()
    
    elif name == "session_switch":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        return await session_switch(arguments["session_name"])
    
    elif name == "session_status":
        return await session_status()
    
    elif name == "session_delete":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        return await session_delete(arguments["session_name"])
    
    elif name == "session_history":
        return await session_history()
    
    elif name == "spider_website":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        depth = arguments.get("depth", 2)
        threads = arguments.get("threads", 10)
        return await spider_website(arguments["url"], depth, threads)
    
    elif name == "form_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        scan_type = arguments.get("scan_type", "comprehensive")
        return await form_analysis(arguments["url"], scan_type)
    
    elif name == "header_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        include_security = arguments.get("include_security", True)
        return await header_analysis(arguments["url"], include_security)
    
    elif name == "ssl_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        port = arguments.get("port", 443)
        return await ssl_analysis(arguments["url"], port)
    
    elif name == "subdomain_enum":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        enum_type = arguments.get("enum_type", "comprehensive")
        return await subdomain_enum(arguments["url"], enum_type)
    
    elif name == "web_audit":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        audit_type = arguments.get("audit_type", "comprehensive")
        return await web_audit(arguments["url"], audit_type)

    elif name == "msf_exploit":
        if "module" not in arguments:
            raise ValueError("Missing required argument 'module'")
        if "rhosts" not in arguments:
            raise ValueError("Missing required argument 'rhosts'")
        options = arguments.get("options", "")
        return await msf_exploit(arguments["module"], arguments["rhosts"], options)
    
    elif name == "nmap_nse_scan":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        if "scripts" not in arguments:
            raise ValueError("Missing required argument 'scripts'")
        ports = arguments.get("ports", "1-65535")
        return await nmap_nse_scan(arguments["target"], arguments["scripts"], ports)

    elif name == "task_list":
        return await task_list()
    
    elif name == "task_stop":
        if "task_id" not in arguments:
            raise ValueError("Missing required argument 'task_id'")
        return await task_stop(arguments["task_id"])
    
    elif name == "task_logs":
        if "task_id" not in arguments:
            raise ValueError("Missing required argument 'task_id'")
        lines = arguments.get("lines", 20)
        return await task_logs(arguments["task_id"], lines)
    
    else:
        raise ValueError(f"Unknown tool: {name}")


@kali_server.list_tools()
async def list_available_tools() -> List[types.Tool]:
    """
    Register and list all available MCP tools.
    
    Returns:
        List of available Tool objects
    """
    return [
        types.Tool(
            name="fetch",
            description="Fetches a website and returns its content",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch",
                    }
                },
            },
        ),
        types.Tool(
            name="run",
            description="Runs a shell command on the Kali Linux system",
            inputSchema={
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute",
                    }
                },
            },
        ),
        types.Tool(
            name="resources",
            description="Lists available system resources and command examples",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="vulnerability_scan",
            description="Perform automated vulnerability assessment with multiple tools",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Type of scan (quick, comprehensive, web, network)",
                        "enum": ["quick", "comprehensive", "web", "network"],
                        "default": "comprehensive"
                    }
                },
            },
        ),
        types.Tool(
            name="web_enumeration",
            description="Perform comprehensive web application discovery and enumeration",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL (e.g., http://example.com)",
                    },
                    "enumeration_type": {
                        "type": "string",
                        "description": "Type of enumeration (basic, full, aggressive)",
                        "enum": ["basic", "full", "aggressive"],
                        "default": "full"
                    }
                },
            },
        ),
        types.Tool(
            name="network_discovery",
            description="Perform multi-stage network reconnaissance and discovery",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target network (e.g., 192.168.1.0/24) or host",
                    },
                    "discovery_type": {
                        "type": "string",
                        "description": "Type of discovery (quick, comprehensive, stealth)",
                        "enum": ["quick", "comprehensive", "stealth"],
                        "default": "comprehensive"
                    }
                },
            },
        ),
        types.Tool(
            name="exploit_search",
            description="Search for exploits using searchsploit and other exploit databases",
            inputSchema={
                "type": "object",
                "required": ["search_term"],
                "properties": {
                    "search_term": {
                        "type": "string",
                        "description": "Term to search for (e.g., 'apache', 'ssh', 'CVE-2021-44228')",
                    },
                    "search_type": {
                        "type": "string",
                        "description": "Type of search (all, web, remote, local, dos)",
                        "enum": ["all", "web", "remote", "local", "dos"],
                        "default": "all"
                    }
                },
            },
        ),
        types.Tool(
            name="save_output",
            description="Save content to a timestamped file for evidence collection",
            inputSchema={
                "type": "object",
                "required": ["content"],
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Content to save",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional custom filename (without extension)",
                    },
                    "category": {
                        "type": "string",
                        "description": "Category for organizing files (e.g., 'scan', 'enum', 'evidence')",
                        "default": "general"
                    }
                },
            },
        ),
        types.Tool(
            name="create_report",
            description="Generate a structured report from findings",
            inputSchema={
                "type": "object",
                "required": ["title", "findings"],
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Report title",
                    },
                    "findings": {
                        "type": "string",
                        "description": "Findings content",
                    },
                    "report_type": {
                        "type": "string",
                        "description": "Type of report (markdown, text, json)",
                        "enum": ["markdown", "text", "json"],
                        "default": "markdown"
                    }
                },
            },
        ),
        types.Tool(
            name="file_analysis",
            description="Analyze a file using various tools (file type, strings, hash)",
            inputSchema={
                "type": "object",
                "required": ["filepath"],
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to the file to analyze",
                    }
                },
            },
        ),
        types.Tool(
            name="download_file",
            description="Download a file from a URL and save it locally",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to download from",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional custom filename",
                    }
                },
            },
        ),
        types.Tool(
            name="session_create",
            description="Create a new pentest session (name, description, target)",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {
                        "type": "string",
                        "description": "Name of the session",
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the session",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target for the session",
                    }
                },
            },
        ),
        types.Tool(
            name="session_list",
            description="List all pentest sessions with metadata",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="session_switch",
            description="Switch to a different pentest session",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {
                        "type": "string",
                        "description": "Name of the session to switch to",
                    }
                },
            },
        ),
        types.Tool(
            name="session_status",
            description="Show current session status and summary",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="session_delete",
            description="Delete a pentest session and all its evidence",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {
                        "type": "string",
                        "description": "Name of the session to delete",
                    }
                },
            },
        ),
        types.Tool(
            name="session_history",
            description="Show command/evidence history for the current session",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="spider_website",
            description="Spider a website to find all links and resources",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the website to spider",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Maximum depth of the spider",
                        "default": 2
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 10
                    }
                },
            },
        ),
        types.Tool(
            name="form_analysis",
            description="Analyze a web form for vulnerabilities",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the web form to analyze",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Type of scan (comprehensive, quick)",
                        "enum": ["comprehensive", "quick"],
                        "default": "comprehensive"
                    }
                },
            },
        ),
        types.Tool(
            name="header_analysis",
            description="Analyze HTTP headers for security issues",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the website to analyze",
                    },
                    "include_security": {
                        "type": "boolean",
                        "description": "Include security-related headers",
                        "default": True
                    }
                },
            },
        ),
        types.Tool(
            name="ssl_analysis",
            description="Analyze SSL/TLS configuration of a website",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the website to analyze",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port to connect to",
                        "default": 443
                    }
                },
            },
        ),
        types.Tool(
            name="subdomain_enum",
            description="Enumerate subdomains of a target website",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the target website",
                    },
                    "enum_type": {
                        "type": "string",
                        "description": "Type of enumeration (comprehensive, quick)",
                        "enum": ["comprehensive", "quick"],
                        "default": "comprehensive"
                    }
                },
            },
        ),
        types.Tool(
            name="web_audit",
            description="Perform a comprehensive web application audit",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the website to audit",
                    },
                    "audit_type": {
                        "type": "string",
                        "description": "Type of audit (comprehensive, quick)",
                        "enum": ["comprehensive", "quick"],
                        "default": "comprehensive"
                    }
                },
            },
        ),
        types.Tool(
            name="msf_exploit",
            description="Execute a Metasploit module against a target",
            inputSchema={
                "type": "object",
                "required": ["module", "rhosts"],
                "properties": {
                    "module": {
                        "type": "string",
                        "description": "Metasploit module (e.g., 'exploit/windows/smb/ms17_010_eternalblue')",
                    },
                    "rhosts": {
                        "type": "string",
                        "description": "Target host(s)",
                    },
                    "options": {
                        "type": "string",
                        "description": "Additional MSF options (e.g., 'PAYLOAD=windows/x64/meterpreter/reverse_tcp')",
                    }
                },
            },
        ),
        types.Tool(
            name="nmap_nse_scan",
            description="Perform targeted Nmap NSE script scan",
            inputSchema={
                "type": "object",
                "required": ["target", "scripts"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "scripts": {
                        "type": "string",
                        "description": "NSE scripts to run (e.g., 'vuln', 'http-enum')",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Ports to scan",
                        "default": "1-65535"
                    }
                },
            },
        ),
        types.Tool(
            name="task_list",
            description="List all background security tasks",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="task_stop",
            description="Stop a running background task",
            inputSchema={
                "type": "object",
                "required": ["task_id"],
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "ID of the task to stop",
                    }
                },
            },
        ),
        types.Tool(
            name="task_logs",
            description="Get real-time logs for a background task",
            inputSchema={
                "type": "object",
                "required": ["task_id"],
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "ID of the task to get logs for",
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Number of lines to return",
                        "default": 20
                    }
                },
            },
        ),
    ]


@click.command()
@click.option("--port", default=8000, help="Port to listen on for HTTP/SSE connections")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="sse",
    help="Transport type (stdio for command line, sse for Claude Desktop)"
)
@click.option(
    "--debug", 
    is_flag=True, 
    default=False, 
    help="Enable debug mode"
)
def main(port: int, transport: str, debug: bool) -> int:
    """
    Start the Kali MCP Server with the specified transport.
    
    Args:
        port: Port number to listen on when using SSE transport
        transport: Transport type (stdio or SSE)
        debug: Enable debug mode
        
    Returns:
        Exit code (0 for success)
    """
    if transport == "sse":
        return start_sse_server(port, debug)
    else:
        return start_stdio_server(debug)


def start_sse_server(port: int, debug: bool) -> int:
    """
    Start the server with SSE transport for web/Claude Desktop usage.
    
    Args:
        port: Port number to listen on
        debug: Enable debug mode
        
    Returns:
        Exit code (0 for success)
    """
    import uvicorn
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    # Create SSE transport handler
    sse_transport = SseServerTransport("/messages/")

    async def handle_sse_connection(request):
        """Handle incoming SSE connections."""
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await kali_server.run(
                streams[0], streams[1], kali_server.create_initialization_options()
            )

    # Configure Starlette routes
    starlette_app = Starlette(
        debug=debug,
        routes=[
            Route("/sse", endpoint=handle_sse_connection),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ],
    )

    # Run the server
    print(f"Starting Kali MCP Server with SSE transport on port {port}")
    print(f"Connect to this server using: http://localhost:{port}/sse")
    uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    return 0


def start_stdio_server(debug: bool) -> int:
    """
    Start the server with stdio transport for command-line usage.
    
    Args:
        debug: Enable debug mode
        
    Returns:
        Exit code (0 for success)
    """
    from mcp.server.stdio import stdio_server

    async def start_stdio_connection():
        """Initialize and run the stdio server."""
        print("Starting Kali MCP Server with stdio transport")
        async with stdio_server() as streams:
            await kali_server.run(
                streams[0], streams[1], kali_server.create_initialization_options()
            )

    # Run the server
    anyio.run(start_stdio_connection)
    return 0


if __name__ == "__main__":
    main()