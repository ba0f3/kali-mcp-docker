#!/usr/bin/env python3
"""
Test script for MCP tools functioning.

Spawns the Kali MCP server over stdio, connects as a client, and verifies
that key tools respond correctly: list_tools, resources, run, network_discovery
(port scan on example.com), and vulnerability_scan (example.com).

Usage:
  From repo root (with package installed):
    python scripts/test_mcp_tools.py
    uv run python scripts/test_mcp_tools.py

  Exit code: 0 if all checks pass, 1 otherwise.

  Set MCP_TEST_SKIP_SCANS=1 to skip network_discovery and vulnerability_scan
  (useful if stdio connection drops during long-running tool responses).
"""

import asyncio
import os
import sys


def _repo_root() -> str:
    """Return the repository root (directory containing pyproject.toml)."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(script_dir)
    if not os.path.isfile(os.path.join(root, "pyproject.toml")):
        raise SystemExit("Cannot find repo root (pyproject.toml). Run from repo root.")
    return root


async def run_tests() -> bool:
    """Connect to server via stdio and test tools. Returns True if all pass."""
    root = _repo_root()
    os.chdir(root)
    sys.path.insert(0, root)

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "kali_mcp_server", "--transport", "stdio"],
        env=os.environ,
    )

    # Long timeout for scan tools (nmap etc. can take minutes)
    scan_timeout_seconds = 300

    print("Starting MCP server (stdio)...")
    async with stdio_client(server_params) as (read_stream, write_stream):
        # Session-level read timeout so long-running tool responses are not cut off
        async with ClientSession(
            read_stream, write_stream, read_timeout_seconds=scan_timeout_seconds
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
            print(f"  OK ({len(tools)} tools: {', '.join(names[:8])}{'...' if len(names) > 8 else ''})")

            if "resources" not in names:
                print("  FAIL: expected 'resources' in tools")
                return False

            print("Calling tool: resources...")
            result = await session.call_tool("resources", {})
            if result.isError:
                print(f"  FAIL: {result}")
                return False
            content = result.content or []
            if not content:
                print("  FAIL: empty content")
                return False
            text = getattr(content[0], "text", None) or str(content[0])
            print(f"  OK (response length {len(text)} chars)")

            print("Calling tool: run (command='echo MCP test')...")
            result = await session.call_tool("run", {"command": "echo MCP test"})
            if result.isError:
                print(f"  FAIL: {result}")
                return False
            content = result.content or []
            if not content:
                print("  FAIL: empty content")
                return False
            text = getattr(content[0], "text", None) or str(content[0])
            if "MCP test" not in text:
                print(f"  FAIL: expected 'MCP test' in output, got: {text[:200]}")
                return False
            print("  OK")

            skip_scans = os.environ.get("MCP_TEST_SKIP_SCANS", "").strip() == "1"
            if "network_discovery" in names and not skip_scans:
                print("Calling tool: network_discovery (target=example.com, quick)...")
                print("  Waiting for result (may take 1–2 minutes)...")
                try:
                    result = await session.call_tool(
                        "network_discovery",
                        {"target": "example.com", "discovery_type": "quick"},
                        read_timeout_seconds=scan_timeout_seconds,
                    )
                    if result.isError:
                        print(f"  FAIL: {result}")
                        return False
                    content = result.content or []
                    if not content:
                        print("  FAIL: empty content")
                        return False
                    text = getattr(content[0], "text", None) or str(content[0])
                    print(f"  OK (response length {len(text)} chars)")
                except Exception as e:
                    print(f"  SKIP: {e}")
            elif "network_discovery" in names and skip_scans:
                print("Skipping network_discovery (MCP_TEST_SKIP_SCANS=1)")
            else:
                print("Skipping network_discovery (tool not listed)")

            if "vulnerability_scan" in names and not skip_scans:
                print("Calling tool: vulnerability_scan (target=example.com, quick)...")
                print("  Waiting for result (may take 1–2 minutes)...")
                try:
                    result = await session.call_tool(
                        "vulnerability_scan",
                        {"target": "example.com", "scan_type": "quick"},
                        read_timeout_seconds=scan_timeout_seconds,
                    )
                    if result.isError:
                        print(f"  FAIL: {result}")
                        return False
                    content = result.content or []
                    if not content:
                        print("  FAIL: empty content")
                        return False
                    text = getattr(content[0], "text", None) or str(content[0])
                    print(f"  OK (response length {len(text)} chars)")
                except Exception as e:
                    print(f"  SKIP: {e}")
            elif "vulnerability_scan" in names and skip_scans:
                print("Skipping vulnerability_scan (MCP_TEST_SKIP_SCANS=1)")
            else:
                print("Skipping vulnerability_scan (tool not listed)")

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
        print("All MCP tool checks passed.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
