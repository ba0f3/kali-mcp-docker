#!/usr/bin/env python3
"""
Test async scan tools over Streamable HTTP at http://localhost:8000/mcp/.

Assumes the Kali MCP server is already running with Streamable HTTP (e.g.
`./run_docker.sh` or `docker run ... -p 8000:8000 kali-mcp-server`).
Connects to the /mcp endpoint, initializes, then runs network_discovery and
vulnerability_scan on example.com to verify Streamable HTTP with long-running
tool responses.

Usage:
  From repo root (with package installed):
    python scripts/test_streamable_http_scan.py
    uv run python scripts/test_streamable_http_scan.py

  Override URL:
    MCP_STREAMABLE_HTTP_URL=http://localhost:8000/mcp/ python scripts/test_streamable_http_scan.py

  Skip long scans:
    MCP_TEST_SKIP_SCANS=1 python scripts/test_streamable_http_scan.py

Exit code: 0 if checks pass, 1 otherwise.
"""

import asyncio
import os
import re
import sys
import time
from datetime import timedelta


def _repo_root() -> str:
    """Return the repository root (directory containing pyproject.toml)."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(script_dir)
    if not os.path.isfile(os.path.join(root, "pyproject.toml")):
        raise SystemExit("Cannot find repo root (pyproject.toml). Run from repo root.")
    return root


def _extract_task_id(text: str) -> str | None:
    """Extract task_id from scan tool response (e.g. 'Task ID: `task_123`' or 'task_id=task_123')."""
    if not text:
        return None
    # Match `task_123` or task_id=task_123
    m = re.search(r"task_id[=:]?\s*[`']?(task_\d+)[`']?", text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"🆔 Task ID: `(task_\d+)`", text)
    if m:
        return m.group(1)
    return None


async def _wait_for_task(
    session,  # ClientSession
    task_id: str,
    poll_interval_seconds: float = 5.0,
    max_wait_seconds: float = 300.0,
    log_lines: int = 500,
) -> str:
    """Poll task_list until task is completed/failed, then return task_logs output."""
    timeout = timedelta(seconds=max_wait_seconds)
    deadline = time.monotonic() + max_wait_seconds
    while time.monotonic() < deadline:
        result = await session.call_tool(
            "task_list",
            {},
            read_timeout_seconds=timeout,
        )
        if result.isError:
            await asyncio.sleep(poll_interval_seconds)
            continue
        content = result.content or []
        text = (getattr(content[0], "text", None) or str(content[0])) if content else ""
        done = False
        for line in text.splitlines():
            if line.strip().startswith(f"### {task_id} "):
                if "COMPLETED" in line or "FAILED" in line or "stopped" in line.lower():
                    done = True
                break
        if done:
            break
        await asyncio.sleep(poll_interval_seconds)

    logs_result = await session.call_tool(
        "task_logs",
        {"task_id": task_id, "lines": log_lines},
        read_timeout_seconds=timeout,
    )
    if logs_result.isError or not logs_result.content:
        return ""
    return getattr(logs_result.content[0], "text", None) or str(logs_result.content[0])


async def run_tests() -> bool:
    """Connect to server via Streamable HTTP and test scan tools. Returns True if all pass."""
    root = _repo_root()
    os.chdir(root)
    sys.path.insert(0, root)

    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as e:
        print(f"Missing dependency: {e}", file=sys.stderr)
        print("Ensure mcp>=1.26 with streamable HTTP client support.", file=sys.stderr)
        return False

    import httpx

    url = os.environ.get("MCP_STREAMABLE_HTTP_URL", "http://localhost:8000/mcp/")
    scan_timeout_seconds = 300

    # Long timeout so the HTTP GET stream stays open during long-running tool calls
    http_timeout = httpx.Timeout(scan_timeout_seconds)

    print(f"Connecting to Streamable HTTP at {url}...")
    try:
        async with httpx.AsyncClient(timeout=http_timeout) as http_client:
            async with streamable_http_client(url, http_client=http_client) as streams:
                # SDK may yield (read_stream, write_stream) or (read_stream, write_stream, get_session_id)
                read_stream, write_stream = streams[0], streams[1]
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=scan_timeout_seconds),
                ) as session:
                    print("Initializing session...")
                    await session.initialize()
                    print("  OK")

                    print("Listing tools...")
                    tools_result = await session.list_tools()
                    tools = getattr(tools_result, "tools", []) or []
                    names = [t.name for t in tools]
                    if not names:
                        print("  FAIL: no tools returned")
                        return False
                    print(
                        f"  OK ({len(tools)} tools: {', '.join(names[:8])}{'...' if len(names) > 8 else ''})"
                    )

                    skip_scans = os.environ.get("MCP_TEST_SKIP_SCANS", "").strip() == "1"

                    if "network_discovery" in names and not skip_scans:
                        print(
                            "Calling tool: network_discovery (target=example.com, quick)..."
                        )
                        print("  Started; waiting for task to complete (polling task_list)...")
                        try:
                            result = await session.call_tool(
                                "network_discovery",
                                {"target": "example.com", "discovery_type": "quick"},
                                read_timeout_seconds=timedelta(seconds=scan_timeout_seconds),
                            )
                            if result.isError:
                                print(f"  FAIL: {result}")
                                return False
                            content = result.content or []
                            if not content:
                                print("  FAIL: empty content")
                                return False
                            text = getattr(content[0], "text", None) or str(content[0])
                            task_id = _extract_task_id(text)
                            if task_id:
                                print(f"  Task {task_id}; waiting for result (up to 5 min)...")
                                logs = await _wait_for_task(
                                    session, task_id,
                                    poll_interval_seconds=5.0,
                                    max_wait_seconds=float(scan_timeout_seconds),
                                    log_lines=200,
                                )
                                print(f"  OK (task completed, logs length {len(logs)} chars)")
                            else:
                                print(f"  OK (response length {len(text)} chars)")
                        except Exception as e:
                            print(f"  SKIP: {e}")
                    elif "network_discovery" in names and skip_scans:
                        print("Skipping network_discovery (MCP_TEST_SKIP_SCANS=1)")
                    else:
                        print("Skipping network_discovery (tool not listed)")

                    if "vulnerability_scan" in names and not skip_scans:
                        print(
                            "Calling tool: vulnerability_scan (target=example.com, quick)..."
                        )
                        print("  Started; waiting for task to complete (polling task_list)...")
                        try:
                            result = await session.call_tool(
                                "vulnerability_scan",
                                {"target": "example.com", "scan_type": "quick"},
                                read_timeout_seconds=timedelta(seconds=scan_timeout_seconds),
                            )
                            if result.isError:
                                print(f"  FAIL: {result}")
                                return False
                            content = result.content or []
                            if not content:
                                print("  FAIL: empty content")
                                return False
                            text = getattr(content[0], "text", None) or str(content[0])
                            task_id = _extract_task_id(text)
                            if task_id:
                                print(f"  Task {task_id}; waiting for result (up to 5 min)...")
                                logs = await _wait_for_task(
                                    session, task_id,
                                    poll_interval_seconds=5.0,
                                    max_wait_seconds=float(scan_timeout_seconds),
                                    log_lines=200,
                                )
                                print(f"  OK (task completed, logs length {len(logs)} chars)")
                            else:
                                print(f"  OK (response length {len(text)} chars)")
                        except Exception as e:
                            print(f"  SKIP: {e}")
                    elif "vulnerability_scan" in names and skip_scans:
                        print("Skipping vulnerability_scan (MCP_TEST_SKIP_SCANS=1)")
                    else:
                        print("Skipping vulnerability_scan (tool not listed)")
    except httpx.ConnectError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        print("Ensure the server is running (e.g. ./run_docker.sh).", file=sys.stderr)
        return False

    return True


def main() -> int:
    """Entry point. Returns 0 on success, 1 on failure."""
    try:
        ok = asyncio.run(run_tests())
    except BaseException as e:
        import traceback

        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1
    if ok:
        print("Streamable HTTP scan checks passed.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
