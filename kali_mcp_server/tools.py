"""
Implementation of MCP tools for the Kali Linux environment.

This module contains the implementations of the tools exposed by the MCP server:
- fetch_website: Fetches content from a specified URL
- kali_terminal: Executes shell commands in the Kali Linux environment
- system_resources: Lists available system resources and command examples
"""

import asyncio
import datetime
import json
import os
import platform
import re
from typing import Optional, Sequence, Union

import httpx
import mcp.types as types

# List of allowed commands for security purposes
# Format: (command_prefix, is_long_running)
ALLOWED_COMMANDS = [
    # System information
    ("uname", False),
    ("whoami", False),
    ("id", False),
    ("uptime", False),
    ("date", False),
    ("free", False),
    ("df", False),
    ("ps", False),
    ("top -n 1", False),
    
    # Network utilities
    ("ping -c", False),  # Allow ping with count parameter
    ("ifconfig", False),
    ("ip", False),
    ("netstat", False),
    ("ss", False),
    ("dig", False),
    ("nslookup", False),
    ("host", False),
    ("curl", False),
    ("wget", False),
    
    # Security tools
    ("nmap", True),  # Long-running
    ("nikto", True),  # Long-running
    ("gobuster", True),  # Long-running
    ("dirb", True),  # Long-running
    ("whois", False),
    ("sqlmap", True),  # Long-running
    ("searchsploit", False),
    ("traceroute", False),
    ("testssl.sh", True),  # Long-running
    ("amass", True),  # Long-running
    ("httpx", True),  # Long-running
    ("subfinder", True),  # Long-running
    ("waybackurls", False),
    ("gospider", True),  # Long-running
    
    # File analysis tools
    ("file", False),
    ("strings", False),
    ("sha256sum", False),
    ("md5sum", False),
    ("wc", False),
    
    # File operations
    ("ls", False),
    # Only allow cat on safe files
    ("cat /proc/", False),
    ("cat /var/log/", False),
    ("cat command_output.txt", False),
    ("cat *.txt", False),
    ("cat *.log", False),
    ("cat vuln_scan_", False),
    ("cat web_enum_", False),
    ("cat network_discovery_", False),
    ("cat exploit_search_", False),
    ("cat file_analysis_", False),
    ("cat report_", False),
    ("cat downloads/", False),
    ("cat spider_", False),
    ("cat form_analysis_", False),
    ("cat header_analysis_", False),
    ("cat ssl_analysis_", False),
    ("cat subdomain_enum_", False),
    ("cat web_audit_", False),
    ("head", False),
    ("tail", False),
    ("find", True),  # Can be long-running
    ("grep", False),
    
    # Utility commands
    ("echo", False),
    ("which", False),
    ("man", False),
    ("help", False),
]

# --- Session Management Backend ---
# Use absolute path for sessions directory to avoid permission issues
# Default to /app/sessions (Docker), fallback to cwd/sessions for local dev
SESSIONS_DIR = os.environ.get("MCP_SESSIONS_DIR", "/app/sessions")
ACTIVE_SESSION_FILE = os.path.join(SESSIONS_DIR, "active_session.txt")

# --- Background Task Management ---
BACKGROUND_TASKS = {} # taskId -> {process, command, startTime, outputFile, status}


def _json_response(
    tool: str,
    success: bool,
    message: str = "",
    data: Optional[dict] = None,
    error: Optional[str] = None,
) -> Sequence[types.TextContent]:
    """Return a single TextContent with JSON payload for all tool responses."""
    payload: dict = {"tool": tool, "success": success}
    if message:
        payload["message"] = message
    if data is not None:
        payload["data"] = data
    if error is not None:
        payload["error"] = error
    return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]


def get_current_session_dir():
    active = load_active_session()
    if active:
        return get_session_path(active)
    # Use absolute path to /app/outputs (or current working directory if /app doesn't exist)
    # This ensures we always write to a writable location
    cwd = os.getcwd()
    outputs_dir = os.path.join(cwd, "outputs")
    # Ensure outputs directory exists and is writable
    try:
        os.makedirs(outputs_dir, exist_ok=True)
        return outputs_dir
    except (OSError, PermissionError):
        # Fallback to current directory if we can't create outputs/
        return cwd

def get_output_path(filename: str) -> str:
    """Prepend the current session directory if active and path is relative."""
    if os.path.isabs(filename) or filename.startswith(SESSIONS_DIR):
        return filename
    base_dir = get_current_session_dir()
    # Ensure we return an absolute path
    result = os.path.join(base_dir, filename)
    return os.path.abspath(result)

async def register_background_task(command: str, output_file: str) -> str:
    """Register and start a background task."""
    task_id = f"task_{int(asyncio.get_event_loop().time())}"
    
    # Ensure output_file is absolute so redirects write to the same file we touch
    output_file = get_output_path(output_file)
    output_basename = os.path.basename(output_file)
    # Command was built with relative filename; replace redirects with absolute path
    command = command.replace(f">> {output_basename}", f">> {output_file}")

    # Ensure directory exists and create output file so task_logs can read it immediately
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    header = (
        f"=== Task started at {datetime.datetime.now().isoformat()} ===\n"
        f"Command: {command}\n"
        f"---\n"
    )
    with open(output_file, "w") as f:
        f.write(header)

    process = await asyncio.create_subprocess_shell(
        f"{command} >> {output_file} 2>&1",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    
    BACKGROUND_TASKS[task_id] = {
        "process": process,
        "command": command,
        "startTime": datetime.datetime.now().isoformat(),
        "outputFile": output_file,
        "status": "running"
    }
    
    # Update session history if active
    active_session = load_active_session()
    if active_session:
        try:
            metadata_path = get_session_metadata_path(active_session)
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            metadata["history"].append({
                "timestamp": datetime.datetime.now().isoformat(),
                "action": "background_task_start",
                "details": f"Started {command} (Task ID: {task_id})",
                "output_file": output_file
            })
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception:
            pass # Silently fail history update
    
    # Monitor the task in the background
    asyncio.create_task(monitor_task(task_id))
    
    return task_id

async def monitor_task(task_id: str):
    """Monitor a background task until completion."""
    task = BACKGROUND_TASKS.get(task_id)
    if not task:
        return
    
    process = task["process"]
    await process.wait()
    
    task["status"] = "completed" if process.returncode == 0 else "failed"
    task["endTime"] = datetime.datetime.now().isoformat()
    task["exitCode"] = process.returncode

async def task_list() -> list:
    """List all background tasks."""
    if not BACKGROUND_TASKS:
        return _json_response("task_list", True, "No background tasks found.", data={"tasks": []})
    tasks = []
    for tid, info in BACKGROUND_TASKS.items():
        tasks.append({
            "task_id": tid,
            "status": info["status"],
            "command": info["command"],
            "start_time": info["startTime"],
            "end_time": info.get("endTime"),
            "output_file": info["outputFile"],
        })
    return _json_response("task_list", True, f"Found {len(tasks)} task(s).", data={"tasks": tasks})

async def task_stop(task_id: str) -> list:
    """Stop a running background task."""
    task = BACKGROUND_TASKS.get(task_id)
    if not task:
        return _json_response("task_stop", False, error=f"Task '{task_id}' not found.")
    if task["status"] != "running":
        return _json_response("task_stop", False, error=f"Task '{task_id}' is already {task['status']}.")
    try:
        task["process"].terminate()
        task["status"] = "stopped"
        task["endTime"] = datetime.datetime.now().isoformat()
        return _json_response("task_stop", True, f"Task '{task_id}' stopped.", data={"task_id": task_id})
    except Exception as e:
        return _json_response("task_stop", False, error=str(e))

async def task_logs(task_id: str, lines: int = 20) -> list:
    """Get the tail of logs for a background task."""
    task = BACKGROUND_TASKS.get(task_id)
    if not task:
        return _json_response("task_logs", False, error=f"Task '{task_id}' not found.")
    output_file = task["outputFile"]
    if not os.path.exists(output_file):
        return _json_response("task_logs", False, message="Output file not found yet.", data={"task_id": task_id, "output_file": output_file})
    try:
        with open(output_file, 'r') as f:
            log_lines = f.readlines()
            tail = "".join(log_lines[-lines:])
        data = {
            "task_id": task_id,
            "status": task["status"],
            "output_file": output_file,
            "lines_shown": lines,
            "content": tail,
        }
        if task.get("status") == "failed" and "exitCode" in task:
            data["exit_code"] = task["exitCode"]
        return _json_response("task_logs", True, f"Logs for {task_id}.", data=data)
    except Exception as e:
        return _json_response("task_logs", False, error=str(e))

def ensure_sessions_dir():
    """Ensure sessions directory exists with proper permissions."""
    global SESSIONS_DIR, ACTIVE_SESSION_FILE
    try:
        os.makedirs(SESSIONS_DIR, exist_ok=True)
    except (OSError, PermissionError) as e:
        # If /app/sessions fails, try cwd/sessions as fallback (for local dev)
        if SESSIONS_DIR == "/app/sessions":
            fallback_dir = os.path.join(os.getcwd(), "sessions")
            try:
                os.makedirs(fallback_dir, exist_ok=True)
                SESSIONS_DIR = fallback_dir
                ACTIVE_SESSION_FILE = os.path.join(SESSIONS_DIR, "active_session.txt")
            except Exception:
                raise RuntimeError(f"Cannot create sessions directory (tried {SESSIONS_DIR} and {fallback_dir}): {e}")
        else:
            raise RuntimeError(f"Cannot create sessions directory {SESSIONS_DIR}: {e}")


def get_session_path(session_name):
    return os.path.join(SESSIONS_DIR, session_name)


def get_session_metadata_path(session_name):
    return os.path.join(get_session_path(session_name), "metadata.json")


def list_sessions():
    ensure_sessions_dir()
    return [d for d in os.listdir(SESSIONS_DIR) if os.path.isdir(get_session_path(d))]


def save_active_session(session_name):
    ensure_sessions_dir()
    with open(ACTIVE_SESSION_FILE, "w") as f:
        f.write(session_name)


def load_active_session():
    try:
        with open(ACTIVE_SESSION_FILE, "r") as f:
            return f.read().strip()
    except Exception:
        return None


def create_session(session_name, description, target):
    ensure_sessions_dir()
    session_dir = get_session_path(session_name)
    if os.path.exists(session_dir):
        raise ValueError(f"Session '{session_name}' already exists.")
    os.makedirs(session_dir)
    metadata = {
        "name": session_name,
        "description": description,
        "target": target,
        "created": datetime.datetime.now().isoformat(),
        "history": []
    }
    with open(get_session_metadata_path(session_name), "w") as f:
        json.dump(metadata, f, indent=2)
    save_active_session(session_name)
    return metadata

# --- Session Management Tools ---

async def session_create(session_name: str, description: str = "", target: str = "") -> list:
    """
    Create a new pentest session.
    Args:
        session_name: Name of the session
        description: Description of the session
        target: Target for the session
    Returns:
        List containing TextContent with session creation result
    """
    try:
        metadata = create_session(session_name, description, target)
        return _json_response("session_create", True, f"Session '{session_name}' created and set as active.", data=metadata)
    except ValueError as e:
        return _json_response("session_create", False, error=str(e))
    except Exception as e:
        return _json_response("session_create", False, error=str(e))


async def session_list() -> list:
    """
    List all pentest sessions with metadata.
    Returns:
        List containing TextContent with session list
    """
    try:
        sessions = list_sessions()
        active_session = load_active_session()
        if not sessions:
            return _json_response("session_list", True, "No sessions found.", data={"sessions": [], "active_session": None})
        list_data = []
        for sn in sessions:
            try:
                with open(get_session_metadata_path(sn), 'r') as f:
                    meta = json.load(f)
                list_data.append({
                    "session_name": sn,
                    "active": sn == active_session,
                    "description": meta.get("description", ""),
                    "target": meta.get("target", ""),
                    "created": meta.get("created", ""),
                    "history_count": len(meta.get("history", [])),
                })
            except Exception as e:
                list_data.append({"session_name": sn, "active": sn == active_session, "error": str(e)})
        return _json_response("session_list", True, f"Found {len(list_data)} session(s).", data={"sessions": list_data, "active_session": active_session})
    except Exception as e:
        return _json_response("session_list", False, error=str(e))


async def session_switch(session_name: str) -> list:
    """
    Switch to a different pentest session.
    Args:
        session_name: Name of the session to switch to
    Returns:
        List containing TextContent with switch result
    """
    try:
        sessions = list_sessions()
        if session_name not in sessions:
            return _json_response("session_switch", False, error=f"Session '{session_name}' not found.")
        save_active_session(session_name)
        try:
            with open(get_session_metadata_path(session_name), 'r') as f:
                metadata = json.load(f)
            return _json_response("session_switch", True, f"Switched to session '{session_name}'.", data=metadata)
        except Exception as e:
            return _json_response("session_switch", True, f"Switched to '{session_name}' (metadata load failed).", data={"error": str(e)})
    except Exception as e:
        return _json_response("session_switch", False, error=str(e))


async def session_status() -> list:
    """
    Show current session status and summary.
    Returns:
        List containing TextContent with current session status
    """
    try:
        active_session = load_active_session()
        if not active_session:
            return _json_response("session_status", False, message="No active session.", data={})
        try:
            with open(get_session_metadata_path(active_session), 'r') as f:
                metadata = json.load(f)
            session_dir = get_session_path(active_session)
            file_count = len([f for f in os.listdir(session_dir) if os.path.isfile(os.path.join(session_dir, f)) and f != "metadata.json"]) if os.path.exists(session_dir) else 0
            history = metadata.get("history", [])
            data = {
                "active_session": active_session,
                "description": metadata.get("description", ""),
                "target": metadata.get("target", ""),
                "created": metadata.get("created", ""),
                "history_count": len(history),
                "session_file_count": file_count,
                "recent_activity": [{"timestamp": h.get("timestamp"), "action": h.get("action"), "details": h.get("details")} for h in history[-5:]],
            }
            return _json_response("session_status", True, f"Active session: {active_session}.", data=data)
        except Exception as e:
            return _json_response("session_status", False, message=f"Metadata could not be loaded: {e}", data={"active_session": active_session})
    except Exception as e:
        return _json_response("session_status", False, error=str(e))


async def session_delete(session_name: str) -> list:
    """
    Delete a pentest session and all its evidence.
    Args:
        session_name: Name of the session to delete
    Returns:
        List containing TextContent with deletion result
    """
    try:
        sessions = list_sessions()
        if session_name not in sessions:
            return _json_response("session_delete", False, error=f"Session '{session_name}' not found.")
        active_session = load_active_session()
        if session_name == active_session:
            return _json_response("session_delete", False, error="Cannot delete active session. Switch first.")
        try:
            with open(get_session_metadata_path(session_name), 'r') as f:
                metadata = json.load(f)
            deleted_info = {"description": metadata.get("description"), "target": metadata.get("target"), "created": metadata.get("created"), "history_count": len(metadata.get("history", []))}
        except Exception:
            deleted_info = {}
        import shutil
        shutil.rmtree(get_session_path(session_name))
        return _json_response("session_delete", True, f"Session '{session_name}' deleted.", data={"deleted_session": session_name, "details": deleted_info})
    except Exception as e:
        return _json_response("session_delete", False, error=str(e))


async def session_history() -> list:
    """
    Show command/evidence history for the current session.
    Returns:
        List containing TextContent with session history
    """
    try:
        active_session = load_active_session()
        if not active_session:
            return _json_response("session_history", False, message="No active session.", data={"history": []})
        try:
            with open(get_session_metadata_path(active_session), 'r') as f:
                metadata = json.load(f)
            history = metadata.get("history", [])
            items = [{"timestamp": h.get("timestamp"), "action": h.get("action"), "details": h.get("details")} for h in reversed(history)]
            return _json_response("session_history", True, f"History for '{active_session}' ({len(items)} items).", data={"session": active_session, "history": items})
        except Exception as e:
            return _json_response("session_history", False, message=str(e), data={"session": active_session})
    except Exception as e:
        return _json_response("session_history", False, error=str(e))


async def fetch_website(url: str) -> Sequence[Union[types.TextContent, types.ImageContent, types.EmbeddedResource]]:
    """
    Fetch content from a specified URL.
    
    Args:
        url: The URL to fetch content from
        
    Returns:
        List containing TextContent with the website content
        
    Raises:
        ValueError: If the URL is invalid
        httpx.HTTPError: If the request fails
    """
    # Basic URL validation
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    
    # Set user agent to identify the client
    headers = {
        "User-Agent": "Kali MCP Server (github.com/modelcontextprotocol/python-sdk)"
    }
    
    # Fetch the URL with timeout and redirect following
    async with httpx.AsyncClient(
        follow_redirects=True, 
        headers=headers,
        timeout=30.0
    ) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            return _json_response("fetch", True, "Content fetched.", data={"url": url, "status_code": response.status_code, "content": response.text})
        except httpx.TimeoutException:
            return _json_response("fetch", False, error="Request timed out after 30 seconds")
        except httpx.HTTPStatusError as e:
            return _json_response("fetch", False, error=f"HTTP {e.response.status_code} - {e.response.reason_phrase}")
        except httpx.RequestError as e:
            return _json_response("fetch", False, error=str(e))


def is_command_allowed(command: str) -> tuple[bool, bool]:
    """
    Check if a command is allowed to run and if it's potentially long-running.
    
    Args:
        command: The shell command to check
        
    Returns:
        Tuple of (is_allowed, is_long_running)
    """
    # Clean the command for checking
    clean_command = command.strip().lower()
    
    # Check against the allowed commands list
    for allowed_prefix, is_long_running in ALLOWED_COMMANDS:
        if clean_command.startswith(allowed_prefix):
            return True, is_long_running
    
    return False, False


async def run_command(command: str) -> Sequence[types.TextContent]:
    """
    Execute a shell command in the Kali Linux environment.
    
    Args:
        command: The shell command to execute
        
    Returns:
        List containing TextContent with the command output
        
    Notes:
        - Long-running commands are executed in the background
        - Commands are checked against an allowlist for security
    """
    try:
        # Sanitize the command (basic security measure)
        # Remove potentially dangerous characters
        command = re.sub(r'[;&|]', '', command)
        
        # Check if command is allowed
        is_allowed, is_long_running = is_command_allowed(command)
        
        if not is_allowed:
            return _json_response("run", False, error="Command not allowed for security reasons.")
        if is_long_running:
            task_id = await register_background_task(command, "command_output.txt")
            return _json_response("run", True, "Long-running command started.", data={"task_id": task_id, "command": command})
        
        # For regular commands, use a timeout approach
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Wait for command to complete with timeout
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
            
            output = stdout.decode() if stdout else ""
            err = stderr.decode() if stderr else ""
            return _json_response("run", True, "Command executed.", data={"command": command, "stdout": output, "stderr": err})
        except asyncio.TimeoutError:
            process.kill()
            return _json_response("run", False, error="Command timed out after 60 seconds.")
    except Exception as e:
        return _json_response("run", False, error=str(e))


async def list_system_resources() -> Sequence[types.TextContent]:
    """
    List available system resources and provide command examples.
    
    Returns:
        List containing TextContent with system resources information
    """
    # Get system information
    system_info = {
        "os": platform.system(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "hostname": platform.node()
    }
    
    # Define categories of commands with examples
    resources = {
        "system_info": {
            "description": "Commands to gather system information",
            "commands": {
                "uname -a": "Display kernel information",
                "top -n 1": "Show running processes and resource usage",
                "df -h": "Display disk space usage",
                "free -m": "Show memory usage",
                "uptime": "Display system uptime",
                "ps aux": "List all running processes"
            }
        },
        "network": {
            "description": "Network diagnostic and scanning tools",
            "commands": {
                "ifconfig": "Display network interfaces",
                "ping -c 4 google.com": "Test network connectivity",
                "curl https://example.com": "Fetch content from a URL",
                "netstat -tuln": "Show listening ports",
                "nmap -F 127.0.0.1": "Quick network scan (background)",
                "dig example.com": "DNS lookup"
            }
        },
        "security_tools": {
            "description": "Security and penetration testing tools",
            "commands": {
                "nmap -sV -p1-1000 127.0.0.1": "Service version detection scan",
                "nikto -h 127.0.0.1": "Web server security scanner",
                "gobuster dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt": "Directory enumeration",
                "whois example.com": "Domain registration information",
                "sqlmap --url http://example.com --dbs": "SQL injection testing",
                "searchsploit apache": "Search for Apache exploits",
                "traceroute example.com": "Trace network route to target"
            }
        },
        "enhanced_tools": {
            "description": "Enhanced security analysis tools (new)",
            "commands": {
                "/vulnerability_scan target=127.0.0.1 scan_type=quick": "Quick vulnerability assessment",
                "/vulnerability_scan target=127.0.0.1 scan_type=comprehensive": "Comprehensive vulnerability scan",
                "/web_enumeration target=http://example.com enumeration_type=full": "Full web application enumeration",
                "/network_discovery target=192.168.1.0/24 discovery_type=comprehensive": "Network discovery and mapping",
                "/exploit_search search_term=apache search_type=web": "Search for web exploits"
            }
        },
        "file_management": {
            "description": "File management and evidence collection tools (new)",
            "commands": {
                "/save_output content='scan results' filename=my_scan category=scan": "Save content to timestamped file",
                "/create_report title='Security Assessment' findings='Vulnerabilities found' report_type=markdown": "Generate structured report",
                "/file_analysis filepath=./suspicious_file": "Analyze file with multiple tools",
                "/download_file url=https://example.com/file.txt filename=downloaded_file": "Download file from URL"
            }
        },
        "file_operations": {
            "description": "File and directory operations",
            "commands": {
                "ls -la": "List files with details",
                "find . -name '*.py'": "Find Python files in current directory",
                "grep 'pattern' file.txt": "Search for text in a file",
                "cat file.txt": "Display file contents",
                "head -n 10 file.txt": "Show first 10 lines of a file",
                "tail -f logfile.txt": "Follow log file updates"
            }
        },
        "utilities": {
            "description": "Useful utility commands",
            "commands": {
                "date": "Show current date and time",
                "cal": "Display calendar",
                "which command": "Find path to a command",
                "echo $PATH": "Display PATH environment variable",
                "history": "Show command history"
            }
        },
        "background_execution": {
            "description": "Run commands in background and check results",
            "commands": {
                "command > output.txt 2>&1 &": "Run any command in background",
                "cat output.txt": "View output from background commands",
                "jobs": "List background jobs",
                "nohup command &": "Run command immune to hangups"
            }
        }
    }
    
    return _json_response("resources", True, "System resources and command examples.", data={"system_info": system_info, "resources": resources})


async def vulnerability_scan(target: str, scan_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Perform automated vulnerability assessment with multiple tools.
    
    Args:
        target: Target IP address or hostname
        scan_type: Type of scan (quick, comprehensive, web, network)
        
    Returns:
        List containing TextContent with scan results
    """
    timestamp = int(asyncio.get_event_loop().time())
    output_file = f"vuln_scan_{target.replace('.', '_')}_{timestamp}.txt"
    
    scan_commands = []
    
    if scan_type == "quick":
        scan_commands = [
            f"nmap -F -sV {target} >> {output_file} 2>&1",
            f"nikto -h {target} >> {output_file} 2>&1"
        ]
    elif scan_type == "comprehensive":
        scan_commands = [
            f"nmap -sS -sV -O -p- {target} >> {output_file} 2>&1",
            f"nikto -h {target} >> {output_file} 2>&1",
            f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1",
            f"whois {target} >> {output_file} 2>&1"
        ]
    elif scan_type == "web":
        scan_commands = [
            f"nikto -h {target} >> {output_file} 2>&1",
            f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1",
            f"sqlmap --url http://{target} --batch --random-agent --level 1 >> {output_file} 2>&1"
        ]
    elif scan_type == "network":
        scan_commands = [
            f"nmap -sS -sV -O -p- {target} >> {output_file} 2>&1",
            f"nmap --script vuln {target} >> {output_file} 2>&1",
            f"whois {target} >> {output_file} 2>&1"
        ]
    
    # Combined command to run all tasks sequentially in one background process for easier tracking
    full_cmd = " && ".join(scan_commands)
    task_id = await register_background_task(full_cmd, output_file)
    
    return _json_response("vulnerability_scan", True, f"Started {scan_type} vulnerability scan on {target}.", data={"task_id": task_id, "output_file": output_file, "commands_queued": len(scan_commands)})


async def web_enumeration(target: str, enumeration_type: str = "full") -> Sequence[types.TextContent]:
    """
    Perform comprehensive web application discovery and enumeration.
    
    Args:
        target: Target URL (e.g., http://example.com)
        enumeration_type: Type of enumeration (basic, full, aggressive)
        
    Returns:
        List containing TextContent with enumeration results
    """
    timestamp = int(asyncio.get_event_loop().time())
    output_file = f"web_enum_{target.replace('://', '_').replace('/', '_')}_{timestamp}.txt"
    
    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"
    
    enum_commands = []
    
    if enumeration_type == "basic":
        enum_commands = [
            f"nikto -h {target} >> {output_file} 2>&1",
            f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1"
        ]
    elif enumeration_type == "full":
        enum_commands = [
            f"nikto -h {target} >> {output_file} 2>&1",
            f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1",
            f"gobuster vhost -u {target} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt >> {output_file} 2>&1",
            f"curl -I {target} >> {output_file} 2>&1"
        ]
    elif enumeration_type == "aggressive":
        enum_commands = [
            f"nikto -h {target} >> {output_file} 2>&1",
            f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1",
            f"gobuster vhost -u {target} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt >> {output_file} 2>&1",
            f"sqlmap --url {target} --batch --random-agent --level 2 >> {output_file} 2>&1",
            f"dirb {target} /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1"
        ]
    
    full_cmd = " && ".join(enum_commands)
    task_id = await register_background_task(full_cmd, output_file)
    
    return _json_response("web_enumeration", True, f"Started {enumeration_type} web enumeration on {target}.", data={"task_id": task_id, "output_file": output_file})


async def network_discovery(target: str, discovery_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Perform multi-stage network reconnaissance and discovery.
    
    Args:
        target: Target network (e.g., 192.168.1.0/24) or host
        discovery_type: Type of discovery (quick, comprehensive, stealth)
        
    Returns:
        List containing TextContent with discovery results
    """
    timestamp = int(asyncio.get_event_loop().time())
    output_file = f"network_discovery_{target.replace('/', '_')}_{timestamp}.txt"
    
    discovery_commands = []
    
    if discovery_type == "quick":
        discovery_commands = [
            f"nmap -sn {target} >> {output_file} 2>&1",
            f"nmap -F {target} >> {output_file} 2>&1",
            f"ping -c 3 {target} >> {output_file} 2>&1"
        ]
    elif discovery_type == "comprehensive":
        discovery_commands = [
            f"nmap -sn {target} >> {output_file} 2>&1",
            f"nmap -sS -sV -O -p- {target} >> {output_file} 2>&1",
            f"nmap --script discovery {target} >> {output_file} 2>&1",
            f"ping -c 5 {target} >> {output_file} 2>&1",
            f"traceroute {target} >> {output_file} 2>&1"
        ]
    elif discovery_type == "stealth":
        discovery_commands = [
            f"nmap -sS -sV --version-intensity 0 -p 80,443,22,21,25,53 {target} >> {output_file} 2>&1",
            f"nmap --script default {target} >> {output_file} 2>&1",
            f"ping -c 2 {target} >> {output_file} 2>&1"
        ]
    
    full_cmd = " && ".join(discovery_commands)
    task_id = await register_background_task(full_cmd, output_file)
    
    return _json_response("network_discovery", True, f"Started {discovery_type} network discovery on {target}.", data={"task_id": task_id, "output_file": output_file})


# Exploit-DB website search URL (DataTables server-side API returns JSON with X-Requested-With header)
EXPLOIT_DB_SEARCH_URL = "https://www.exploit-db.com/search"


async def exploit_search(search_term: str, search_type: str = "all") -> Sequence[types.TextContent]:
    """
    Search for exploits on https://www.exploit-db.com (Exploit Database website).
    
    Uses the site's search API directly instead of the searchsploit CLI.
    
    Args:
        search_term: Term to search for (e.g., "apache", "ssh", "CVE-2021-44228")
        search_type: Type of search (all, web, remote, local, dos). Maps to Exploit-DB type filter.
        
    Returns:
        List containing TextContent with search results (JSON)
    """
    # Map tool search_type to Exploit-DB type query param (empty = all)
    type_param = ""
    if search_type == "web":
        type_param = "webapps"
    elif search_type == "remote":
        type_param = "remote"
    elif search_type == "local":
        type_param = "local"
    elif search_type == "dos":
        type_param = "dos"

    params = {
        "q": search_term,
        "draw": "1",
        "start": "0",
        "length": "50",
    }
    if type_param:
        params["type"] = type_param

    results_list = []
    total = 0
    error_msg = None
    data: dict = {}

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0),
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
        ) as client:
            response = await client.get(EXPLOIT_DB_SEARCH_URL, params=params)
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        error_msg = "Request to Exploit-DB timed out."
    except httpx.HTTPStatusError as e:
        error_msg = f"Exploit-DB returned HTTP {e.response.status_code}."
    except httpx.RequestError as e:
        error_msg = f"Request failed: {e!s}"
    except (KeyError, json.JSONDecodeError) as e:
        error_msg = f"Invalid response from Exploit-DB: {e!s}"

    if error_msg:
        return _json_response(
            "exploit_search",
            False,
            f"Exploit search for '{search_term}' failed.",
            error=error_msg,
            data={
                "search_url": f"{EXPLOIT_DB_SEARCH_URL}?q={search_term}",
                "results": [],
            },
        )

    total = data.get("recordsFiltered", data.get("recordsTotal", 0))
    raw_rows = data.get("data") or []

    for row in raw_rows:
        desc = row.get("description")
        if isinstance(desc, list) and len(desc) >= 2:
            edb_id, title = desc[0], desc[1]
        else:
            edb_id, title = str(row.get("id", "")), str(row.get("description", ""))
        author = row.get("author_id")
        if isinstance(author, list) and len(author) >= 2:
            author = author[1]
        else:
            author = str(author or "")
        cves = []
        for code in row.get("code") or []:
            if isinstance(code, dict) and code.get("code_type") == "cve":
                cves.append(code.get("code", ""))
        results_list.append({
            "id": edb_id,
            "title": title,
            "type": row.get("type_id", ""),
            "platform": row.get("platform_id", ""),
            "author": author,
            "date": row.get("date_published", ""),
            "cve": ", ".join(cves) if cves else "",
            "url": f"https://www.exploit-db.com/exploits/{edb_id}",
        })

    search_url_with_q = f"{EXPLOIT_DB_SEARCH_URL}?q={search_term}"
    if type_param:
        search_url_with_q += f"&type={type_param}"

    return _json_response(
        "exploit_search",
        True,
        f"Exploit search for '{search_term}' ({search_type}): {total} result(s) from Exploit-DB.",
        data={
            "search_url": search_url_with_q,
            "total": total,
            "results": results_list,
        },
    )


async def save_output(content: str, filename: Optional[str] = None, category: str = "general") -> Sequence[types.TextContent]:
    """
    Save content to a timestamped file for evidence collection.
    
    Args:
        content: Content to save
        filename: Optional custom filename (without extension)
        category: Category for organizing files (e.g., "scan", "enum", "evidence")
        
    Returns:
        List containing TextContent with save confirmation
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if filename:
        # Sanitize filename
        safe_filename = "".join(c for c in filename if c.isalnum() or c in ('-', '_')).rstrip()
        filename_full = f"{category}_{safe_filename}_{timestamp}.txt"
    else:
        filename_full = f"{category}_output_{timestamp}.txt"
    
    output_file = get_output_path(filename_full)
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, 'w') as f:
            f.write(f"# {category.upper()} OUTPUT\n")
            f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
            f.write(f"File: {output_file}\n")
            f.write("-" * 50 + "\n\n")
            f.write(content)
        
        return _json_response("save_output", True, "Content saved successfully.", data={"output_file": output_file, "size_chars": len(content), "preview": content[:200] + ("..." if len(content) > 200 else "")})
    except Exception as e:
        return _json_response("save_output", False, error=str(e))


async def create_report(title: str, findings: str, report_type: str = "markdown") -> Sequence[types.TextContent]:
    """
    Generate a structured report from findings.
    
    Args:
        title: Report title
        findings: Findings content
        report_type: Type of report (markdown, text, json)
        
    Returns:
        List containing TextContent with report content and file location
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_title = "".join(c for c in title if c.isalnum() or c in ('-', '_', ' ')).rstrip()
    filename = f"report_{safe_title.replace(' ', '_')}_{timestamp}.{report_type}"
    report_file = get_output_path(filename)
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(report_file), exist_ok=True)

        if report_type == "markdown":
            report_content = f"""# {title}

**Generated:** {datetime.datetime.now().isoformat()}  
**Report File:** {report_file}

---

## Executive Summary

This report contains findings from security assessment activities.

---

## Findings

{findings}

---

## Recommendations

*Review findings and implement appropriate security measures.*

---

**Report generated by Kali MCP Server**  
*Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""
        elif report_type == "text":
            report_content = f"""SECURITY ASSESSMENT REPORT
{'=' * 50}

Title: {title}
Generated: {datetime.datetime.now().isoformat()}
Report File: {report_file}

FINDINGS
{'-' * 20}

{findings}

RECOMMENDATIONS
{'-' * 20}

Review findings and implement appropriate security measures.

Report generated by Kali MCP Server
Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
        elif report_type == "json":
            report_data = {
                "title": title,
                "generated": datetime.datetime.now().isoformat(),
                "report_file": report_file,
                "findings": findings,
                "recommendations": "Review findings and implement appropriate security measures."
            }
            report_content = json.dumps(report_data, indent=2)
        else:
            return _json_response("create_report", False, error=f"Unsupported report type: {report_type}")
        with open(report_file, 'w') as f:
            f.write(report_content)
        return _json_response("create_report", True, "Report generated successfully.", data={"report_file": report_file, "size_chars": len(report_content), "report_type": report_type})
    except Exception as e:
        return _json_response("create_report", False, error=str(e))


async def file_analysis(filepath: str) -> Sequence[types.TextContent]:
    """
    Analyze a file using various tools (file type, strings, hash).
    
    Args:
        filepath: Path to the file to analyze
        
    Returns:
        List containing TextContent with analysis results
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = "".join(c for c in filepath.split('/')[-1] if c.isalnum() or c in ('-', '_', '.')).rstrip()
    filename = f"file_analysis_{safe_filename}_{timestamp}.txt"
    analysis_file = get_output_path(filename)
    
    analysis_commands = [
        f"file {filepath}",
        f"strings {filepath} | head -50",
        f"sha256sum {filepath}",
        f"ls -la {filepath}",
        f"wc -l {filepath}",
        f"head -10 {filepath}"
    ]
    
    analysis_results = []
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(analysis_file), exist_ok=True)

    for cmd in analysis_commands:
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30.0)
            
            output = stdout.decode() if stdout else ""
            error = stderr.decode() if stderr else ""
            
            if output:
                analysis_results.append(f"## {cmd}\n{output}")
            if error:
                analysis_results.append(f"## {cmd} (ERROR)\n{error}")
        except asyncio.TimeoutError:
            analysis_results.append(f"## {cmd}\nTIMEOUT - Command took too long")
        except Exception as e:
            analysis_results.append(f"## {cmd}\nERROR - {str(e)}")
    
    # Combine all results
    full_analysis = f"""# FILE ANALYSIS REPORT

**File:** {filepath}  
**Analyzed:** {datetime.datetime.now().isoformat()}  
**Analysis File:** {analysis_file}

---

{chr(10).join(analysis_results)}

---

**Analysis completed by Kali MCP Server**
"""
    
    # Save analysis to file
    try:
        with open(analysis_file, 'w') as f:
            f.write(full_analysis)
    except Exception as e:
        return _json_response("file_analysis", False, error=str(e))
    
    return _json_response("file_analysis", True, "File analysis completed.", data={"analysis_file": analysis_file, "size_chars": len(full_analysis), "preview": full_analysis[:500] + ("..." if len(full_analysis) > 500 else "")})


async def download_file(url: str, filename: Optional[str] = None) -> Sequence[types.TextContent]:
    """
    Download a file from a URL and save it locally.
    
    Args:
        url: URL to download from
        filename: Optional custom filename
        
    Returns:
        List containing TextContent with download status
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if not filename:
        # Extract filename from URL
        filename = url.split('/')[-1] if '/' in url else f"downloaded_{timestamp}"
        if '?' in filename:
            filename = filename.split('?')[0]
    
    # Sanitize filename
    safe_filename = "".join(c for c in filename if c.isalnum() or c in ('-', '_', '.')).rstrip()
    if not safe_filename:
        safe_filename = f"downloaded_{timestamp}"
    
    download_rel_path = f"downloads/{safe_filename}"
    download_path = get_output_path(download_rel_path)
    
    # Create downloads directory if it doesn't exist
    os.makedirs(os.path.dirname(download_path), exist_ok=True)
    
    try:
        # Download file
        headers = {
            "User-Agent": "Kali MCP Server (github.com/modelcontextprotocol/python-sdk)"
        }
        
        async with httpx.AsyncClient(
            follow_redirects=True,
            headers=headers,
            timeout=60.0
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            
            # Save file
            with open(download_path, 'wb') as f:
                f.write(response.content)
            
            # Get file info
            file_size = len(response.content)
            content_type = response.headers.get('content-type', 'unknown')
            
            # Generate hash
            import hashlib
            file_hash = hashlib.sha256(response.content).hexdigest()
            
            return _json_response("download_file", True, "File downloaded successfully.", data={"path": download_path, "size_bytes": file_size, "url": url, "content_type": content_type, "sha256": file_hash})
    except httpx.TimeoutException:
        return _json_response("download_file", False, error="Download timed out after 60 seconds")
    except httpx.HTTPStatusError as e:
        return _json_response("download_file", False, error=f"HTTP {e.response.status_code} - {e.response.reason_phrase}")
    except httpx.RequestError as e:
        return _json_response("download_file", False, error=str(e))
    except Exception as e:
        return _json_response("download_file", False, error=str(e))


async def msf_exploit(module: str, rhosts: str, options: str = "") -> Sequence[types.TextContent]:
    """
    Execute a Metasploit module against a target.
    
    Args:
        module: The Metasploit module to use (e.g., 'exploit/windows/smb/ms17_010_eternalblue')
        rhosts: Target host(s)
        options: Additional MSF options (e.g., 'LHOST=10.0.0.1 PAYLOAD=windows/x64/meterpreter/reverse_tcp')
        
    Returns:
        List containing TextContent with execution status
    """
    timestamp = int(asyncio.get_event_loop().time())
    output_file = get_output_path(f"msf_{module.replace('/', '_')}_{timestamp}.txt")
    
    # Construct msfconsole command
    msf_cmd = f"msfconsole -q -x 'use {module}; set RHOSTS {rhosts}; {options}; run; exit'"
    
    task_id = await register_background_task(msf_cmd, output_file)
    
    return _json_response("msf_exploit", True, "Metasploit module execution started.", data={"task_id": task_id, "module": module, "rhosts": rhosts, "output_file": output_file})


async def nmap_nse_scan(target: str, scripts: str, ports: str = "1-65535") -> Sequence[types.TextContent]:
    """
    Perform a targeted Nmap scan with NSE scripts.
    
    Args:
        target: Target IP or hostname
        scripts: NSE scripts to run (e.g., 'vuln', 'http-enum', 'default')
        ports: Ports to scan (default: all)
        
    Returns:
        List containing TextContent with scan status
    """
    timestamp = int(asyncio.get_event_loop().time())
    output_file = get_output_path(f"nmap_nse_{target.replace('.', '_')}_{timestamp}.txt")
    
    nmap_cmd = f"nmap -sV -p{ports} --script {scripts} {target}"
    
    task_id = await register_background_task(nmap_cmd, output_file)
    
    return _json_response("nmap_nse_scan", True, "Nmap NSE script scan started.", data={"task_id": task_id, "scripts": scripts, "target": target, "ports": ports, "output_file": output_file})


async def spider_website(url: str, depth: int = 2, threads: int = 10) -> Sequence[types.TextContent]:
    """
    Perform comprehensive web crawling and spidering.
    
    Args:
        url: Target URL to spider
        depth: Crawling depth (default: 2)
        threads: Number of concurrent threads (default: 10)
        
    Returns:
        List containing TextContent with spidering results
    """
    timestamp = int(asyncio.get_event_loop().time())
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"spider_{safe_url}_{timestamp}.txt"
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    # Use gospider for comprehensive crawling
    spider_cmd = f"gospider -s {url} -d {depth} -c {threads}"
    task_id = await register_background_task(spider_cmd, output_file)
    
    return _json_response("spider_website", True, f"Started website spidering on {url}.", data={"task_id": task_id, "url": url, "depth": depth, "threads": threads, "output_file": get_output_path(output_file)})


async def form_analysis(url: str, scan_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Discover and analyze web forms for security testing.
    
    Args:
        url: Target URL to analyze
        scan_type: Type of analysis (basic, comprehensive, aggressive)
        
    Returns:
        List containing TextContent with form analysis results
    """
    timestamp = int(asyncio.get_event_loop().time())
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"form_analysis_{safe_url}_{timestamp}.txt"
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    # Use httpx-toolkit for form discovery
    if scan_type == "basic":
        form_cmd = f"httpx -u {url} -mc 200 -silent"
    elif scan_type == "comprehensive":
        form_cmd = f"httpx -u {url} -mc 200,301,302,403 -silent"
    else:  # aggressive
        form_cmd = f"httpx -u {url} -mc all -silent"
    
    task_id = await register_background_task(form_cmd, output_file)
    
    return _json_response("form_analysis", True, f"Started web form analysis on {url}.", data={"task_id": task_id, "url": url, "scan_type": scan_type, "output_file": get_output_path(output_file)})


async def header_analysis(url: str, include_security: bool = True) -> Sequence[types.TextContent]:
    """
    Analyze HTTP headers for security information and misconfigurations.
    
    Args:
        url: Target URL to analyze
        include_security: Include security header analysis
        
    Returns:
        List containing TextContent with header analysis results
    """
    timestamp = int(asyncio.get_event_loop().time())
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"header_analysis_{safe_url}_{timestamp}.txt"
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    header_cmd = f"curl -s -I {url}"
    task_id = await register_background_task(header_cmd, output_file)
    
    return _json_response("header_analysis", True, f"Started HTTP header analysis on {url}.", data={"task_id": task_id, "url": url, "output_file": get_output_path(output_file)})


async def ssl_analysis(url: str, port: int = 443) -> Sequence[types.TextContent]:
    """
    Perform SSL/TLS security assessment.
    
    Args:
        url: Target URL to analyze
        port: SSL port (default: 443)
        
    Returns:
        List containing TextContent with SSL analysis results
    """
    timestamp = int(asyncio.get_event_loop().time())
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"ssl_analysis_{safe_url}_{timestamp}.txt"
    
    # Extract domain from URL
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Use testssl.sh for comprehensive SSL analysis
    ssl_cmd = f"testssl.sh --quiet --color 0 {domain}:{port}"
    task_id = await register_background_task(ssl_cmd, output_file)
    
    return _json_response("ssl_analysis", True, f"Started SSL/TLS analysis on {domain}:{port}.", data={"task_id": task_id, "domain": domain, "port": port, "output_file": get_output_path(output_file)})


async def subdomain_enum(url: str, enum_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Perform subdomain enumeration using multiple tools.
    
    Args:
        url: Target domain to enumerate
        enum_type: Type of enumeration (basic, comprehensive, aggressive)
        
    Returns:
        List containing TextContent with subdomain enumeration results
    """
    timestamp = int(asyncio.get_event_loop().time())
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"subdomain_enum_{safe_url}_{timestamp}.txt"
    
    # Extract domain from URL
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    enum_commands = []
    if enum_type == "basic":
        enum_commands = [
            f"subfinder -d {domain} >> {output_file} 2>&1",
            f"amass enum -d {domain} >> {output_file} 2>&1"
        ]
    elif enum_type == "comprehensive":
        enum_commands = [
            f"subfinder -d {domain} >> {output_file} 2>&1",
            f"amass enum -d {domain} >> {output_file} 2>&1",
            f"waybackurls {domain} | grep -o '[^/]*\\.{domain}' | sort -u >> {output_file} 2>&1"
        ]
    else:  # aggressive
        enum_commands = [
            f"subfinder -d {domain} >> {output_file} 2>&1",
            f"amass enum -d {domain} >> {output_file} 2>&1",
            f"waybackurls {domain} | grep -o '[^/]*\\.{domain}' | sort -u >> {output_file} 2>&1",
            f"gospider -s https://{domain} -d 1 -c 5 >> {output_file} 2>&1"
        ]
    
    full_cmd = " && ".join(enum_commands)
    task_id = await register_background_task(full_cmd, output_file)
    
    return _json_response("subdomain_enum", True, f"Started {enum_type} subdomain enumeration on {domain}.", data={"task_id": task_id, "domain": domain, "enum_type": enum_type, "output_file": get_output_path(output_file)})


async def web_audit(url: str, audit_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Perform comprehensive web application security audit.
    
    Args:
        url: Target URL to audit
        audit_type: Type of audit (basic, comprehensive, aggressive)
        
    Returns:
        List containing TextContent with audit results
    """
    timestamp = int(asyncio.get_event_loop().time())
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"web_audit_{safe_url}_{timestamp}.txt"
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    audit_commands = []
    if audit_type == "basic":
        audit_commands = [
            f"nikto -h {url} >> {output_file} 2>&1",
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1"
        ]
    elif audit_type == "comprehensive":
        audit_commands = [
            f"nikto -h {url} >> {output_file} 2>&1",
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1",
            f"gobuster vhost -u {url} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt >> {output_file} 2>&1",
            f"sqlmap --url {url} --batch --random-agent --level 1 >> {output_file} 2>&1",
            f"curl -I {url} | grep -i 'server\\|x-powered-by\\|x-' >> {output_file} 2>&1"
        ]
    else:  # aggressive
        audit_commands = [
            f"nikto -h {url} >> {output_file} 2>&1",
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1",
            f"gobuster vhost -u {url} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt >> {output_file} 2>&1",
            f"sqlmap --url {url} --batch --random-agent --level 2 >> {output_file} 2>&1",
            f"dirb {url} /usr/share/wordlists/dirb/common.txt >> {output_file} 2>&1",
            f"curl -I {url} | grep -i 'server\\|x-powered-by\\|x-' >> {output_file} 2>&1",
            f"testssl.sh --quiet --color 0 {url.replace('http://', '').replace('https://', '').split('/')[0]} >> {output_file} 2>&1"
        ]
    
    full_cmd = " && ".join(audit_commands)
    task_id = await register_background_task(full_cmd, output_file)
    
    return _json_response("web_audit", True, f"Started {audit_type} web audit on {url}.", data={"task_id": task_id, "url": url, "audit_type": audit_type, "output_file": get_output_path(output_file)})

OUTPUT_FILE_PATTERNS = [
    # Core tool outputs
    "command_output.txt",
    "*.txt",
    "*.log",
    "*.out",
    "*.err",
    
    # Security analysis outputs
    "vuln_scan_*.txt",
    "web_enum_*.txt", 
    "network_discovery_*.txt",
    "exploit_search_*.txt",
    
    # File management outputs
    "*_output_*.txt",
    "report_*.markdown",
    "report_*.txt",
    "report_*.json",
    "file_analysis_*.txt",
    "downloads/*",
    
    # Session management outputs
    "sessions/*",
    "sessions/*/metadata.json",
    "sessions/active_session.txt",
    
    # Enhanced web application testing outputs
    "spider_*.txt",
    "form_analysis_*.txt",
    "header_analysis_*.txt",
    "ssl_analysis_*.txt",
    "subdomain_enum_*.txt",
    "web_audit_*.txt",
    "*_nikto",
    "*_dirs",
    "*_vhosts",
    "*_sqlmap",
    "*_dirb",
    "*_ssl",
    "*_subfinder",
    "*_amass",
    "*_wayback",
    "*_gospider"
]
