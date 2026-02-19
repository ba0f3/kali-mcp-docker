#!/usr/bin/env python3
"""
Comprehensive integration test for all MCP tools.

Tests all tools via MCP server (stdio or Streamable HTTP) to ensure they work correctly.
Can be run against a running server or spawn one automatically.

Usage:
  # Test via stdio (spawns server automatically)
  python scripts/test_all_tools.py --transport stdio

  # Test via Streamable HTTP (requires running server)
  python scripts/test_all_tools.py --transport http --url http://localhost:8000/mcp/

  # Skip long-running scans
  python scripts/test_all_tools.py --skip-scans

Exit code: 0 if all tests pass, 1 otherwise.
"""

import argparse
import asyncio
import os
import sys
import time
from datetime import timedelta
from typing import Any, Dict, List, Optional


def _repo_root() -> str:
    """Return the repository root."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(script_dir)
    if not os.path.isfile(os.path.join(root, "pyproject.toml")):
        raise SystemExit("Cannot find repo root. Run from repo root.")
    return root


# Expected content checks: at least one of these substrings must appear in the result (case-insensitive)
TOOL_RESULT_CHECKS: Dict[str, Dict[str, Any]] = {
    "fetch": {
        "expected_any": [
            "example", "Example Domain", "<", "html",
            "Request error", "CERTIFICATE_VERIFY_FAILED", "certificate",
        ],
        "min_length": 20,
    },
    "run": {"expected_any": ["MCP test", "Linux", "Darwin", "uname", "echo"]},
    "resources": {"expected_any": ["run", "nmap", "command", "fetch", "tool"], "min_length": 100},
    "vulnerability_scan": {"expected_any": ["Task ID", "task_", "Started", "Monitor"], "min_length": 20},
    "web_enumeration": {"expected_any": ["Task ID", "task_", "Started", "enumeration"], "min_length": 20},
    "network_discovery": {"expected_any": ["Task ID", "task_", "Started", "discovery"], "min_length": 20},
    "exploit_search": {
        "expected_any": [
            "Exploit", "search", "result", "CVE", "exploit-db.com", "search_url",
            "No Results", "total", "results",
        ],
        "min_length": 20,
    },
    "save_output": {"expected_any": ["saved", "Content saved", "output", "success"], "min_length": 10},
    "create_report": {"expected_any": ["Report", "generated", "success", "report_"], "min_length": 10},
    "session_create": {"expected_any": ["created", "Session", "active", "test_session"], "min_length": 10},
    "session_list": {"expected_any": ["Sessions", "No sessions", "session", "ACTIVE", "INACTIVE"], "min_length": 5},
    "session_status": {"expected_any": ["Active Session", "No active session", "session"], "min_length": 5},
    "session_history": {"expected_any": ["History", "No history", "history"], "min_length": 5},
    "task_list": {"expected_any": ["Tasks", "No background", "task_", "📋"], "min_length": 5},
    "spider_website": {"expected_any": ["Task ID", "task_", "Started", "spider", "Spider"], "min_length": 20},
    "form_analysis": {"expected_any": ["Task ID", "task_", "Started", "form", "Form"], "min_length": 20},
    "header_analysis": {"expected_any": ["Header", "HTTP", "Task ID", "task_", "Content-Type"], "min_length": 20},
    "ssl_analysis": {"expected_any": ["SSL", "certificate", "TLS", "Task ID", "task_"], "min_length": 20},
    "subdomain_enum": {"expected_any": ["Task ID", "task_", "Started", "subdomain"], "min_length": 20},
    "web_audit": {"expected_any": ["Task ID", "task_", "Started", "audit"], "min_length": 20},
    "nmap_nse_scan": {"expected_any": ["Task ID", "task_", "Started", "nmap"], "min_length": 20},
}

# Test cases for each tool
TOOL_TESTS: Dict[str, List[Dict[str, Any]]] = {
    "fetch": [
        {"url": "https://example.com"},
    ],
    "run": [
        {"command": "echo 'MCP test'"},
        {"command": "uname -a"},
    ],
    "resources": [
        {},
    ],
    "vulnerability_scan": [
        {"target": "example.com", "scan_type": "quick"},
    ],
    "web_enumeration": [
        {"target": "http://example.com", "enumeration_type": "basic"},
    ],
    "network_discovery": [
        {"target": "example.com", "discovery_type": "quick"},
    ],
    "exploit_search": [
        {"search_term": "apache", "search_type": "web"},
    ],
    "save_output": [
        {"content": "Test output content", "filename": "test_output", "category": "test"},
    ],
    "create_report": [
        {"title": "Test Report", "findings": "Test finding 1\nTest finding 2", "report_type": "markdown"},
    ],
    "session_create": [
        {"session_name": "test_session", "description": "Test session", "target": "test.example.com"},
    ],
    "session_list": [
        {},
    ],
    "session_status": [
        {},
    ],
    "session_history": [
        {},
    ],
    "task_list": [
        {},
    ],
    "spider_website": [
        {"url": "http://example.com", "depth": 1, "threads": 2},
    ],
    "form_analysis": [
        {"url": "http://example.com", "scan_type": "quick"},
    ],
    "header_analysis": [
        {"url": "http://example.com", "include_security": True},
    ],
    "ssl_analysis": [
        {"url": "example.com", "port": 443},
    ],
    "subdomain_enum": [
        {"url": "example.com", "enum_type": "quick"},
    ],
    "web_audit": [
        {"url": "http://example.com", "audit_type": "quick"},
    ],
    "nmap_nse_scan": [
        {"target": "example.com", "scripts": "http-title", "ports": "80"},
    ],
}


async def test_tool(
    session: Any,
    tool_name: str,
    test_case: Dict[str, Any],
    skip_scans: bool = False,
    timeout_seconds: float = 30.0,
) -> tuple[bool, str]:
    """Test a single tool call. Returns (success, message)."""
    # Skip long-running scans if requested
    if skip_scans and tool_name in ("vulnerability_scan", "network_discovery", "web_enumeration"):
        return True, "SKIPPED (long-running scan)"

    try:
        result = await session.call_tool(
            tool_name,
            test_case,
            read_timeout_seconds=timedelta(seconds=timeout_seconds),
        )

        if result.isError:
            return False, f"Tool returned error: {result}"

        if not result.content:
            return False, "Tool returned empty content"

        # Check that we got at least one text content item
        text_content = None
        for item in result.content:
            if hasattr(item, "text"):
                text_content = item.text
                break

        if not text_content:
            return False, "No text content in response"

        # Basic validation: response should not be empty
        text = text_content.strip()
        if len(text) == 0:
            return False, "Response text is empty"

        # Content validation: check tool result contains expected data
        checks = TOOL_RESULT_CHECKS.get(tool_name)
        if checks:
            if checks.get("min_length") and len(text) < checks["min_length"]:
                return False, f"Result too short ({len(text)} chars, expected >={checks['min_length']})"
            expected_any = checks.get("expected_any")
            if expected_any:
                text_lower = text.lower()
                if not any(s.lower() in text_lower for s in expected_any):
                    return False, (
                        f"Result missing expected content (none of: {expected_any[:5]}...). "
                        f"Got: {text[:120]!r}..."
                    )
            forbid = checks.get("forbid")
            if forbid:
                for s in forbid:
                    if s.lower() in text.lower():
                        return False, f"Result must not contain: {s!r}"

        return True, f"OK (response length: {len(text)} chars)"

    except Exception as e:
        return False, f"Exception: {str(e)}"


async def test_all_tools_stdio(skip_scans: bool = False) -> bool:
    """Test all tools via stdio transport."""
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

    print("Starting MCP server (stdio)...")
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            print("Initializing session...")
            await session.initialize()
            print("  ✓ Initialized")

            return await run_tests(session, skip_scans)


async def test_all_tools_http(url: str, skip_scans: bool = False) -> bool:
    """Test all tools via Streamable HTTP transport."""
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

    http_timeout = httpx.Timeout(60.0)
    print(f"Connecting to Streamable HTTP at {url}...")
    try:
        async with httpx.AsyncClient(timeout=http_timeout) as http_client:
            async with streamable_http_client(url, http_client=http_client) as streams:
                read_stream, write_stream = streams[0], streams[1]
                async with ClientSession(read_stream, write_stream) as session:
                    print("Initializing session...")
                    await session.initialize()
                    print("  ✓ Initialized")

                    return await run_tests(session, skip_scans)
    except httpx.ConnectError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        print("Ensure the server is running (e.g. ./run_docker.sh).", file=sys.stderr)
        return False


async def run_tests(session: Any, skip_scans: bool) -> bool:
    """Run all tool tests. Returns True if all pass."""
    print("\nListing available tools...")
    tools_result = await session.list_tools()
    tools = getattr(tools_result, "tools", []) or []
    tool_names = {t.name for t in tools}
    print(f"  Found {len(tools)} tools")

    if not tool_names:
        print("  ✗ FAIL: No tools found")
        return False

    # Filter to only test tools we have test cases for
    tools_to_test = {name for name in TOOL_TESTS.keys() if name in tool_names}
    missing_tests = tool_names - set(TOOL_TESTS.keys())
    if missing_tests:
        print(f"  ⚠ Note: {len(missing_tests)} tools without test cases: {', '.join(sorted(missing_tests)[:5])}")

    print(f"\nTesting {len(tools_to_test)} tools...")
    print("=" * 70)

    passed = 0
    failed = 0
    skipped = 0
    results = []

    for tool_name in sorted(tools_to_test):
        test_cases = TOOL_TESTS[tool_name]
        for i, test_case in enumerate(test_cases):
            test_name = f"{tool_name}" + (f" (case {i+1})" if len(test_cases) > 1 else "")
            print(f"\n[{passed + failed + skipped + 1}/{len(tools_to_test)}] Testing {test_name}...", end=" ", flush=True)

            success, message = await test_tool(session, tool_name, test_case, skip_scans=skip_scans)
            results.append((tool_name, test_case, success, message))

            if success:
                if "SKIPPED" in message:
                    skipped += 1
                    print(f"⏭ SKIP")
                else:
                    passed += 1
                    print(f"✓ PASS")
            else:
                failed += 1
                print(f"✗ FAIL: {message}")

    print("\n" + "=" * 70)
    print(f"\nResults:")
    print(f"  ✓ Passed:  {passed}")
    print(f"  ✗ Failed:  {failed}")
    print(f"  ⏭ Skipped: {skipped}")
    print(f"  Total:    {passed + failed + skipped}")

    if failed > 0:
        print("\nFailed tests:")
        for tool_name, test_case, success, message in results:
            if not success:
                print(f"  ✗ {tool_name}({test_case}): {message}")

    return failed == 0


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="Test all MCP tools")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport to use (default: stdio)",
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000/mcp/",
        help="Streamable HTTP URL (default: http://localhost:8000/mcp/)",
    )
    parser.add_argument(
        "--skip-scans",
        action="store_true",
        help="Skip long-running scan tests",
    )

    args = parser.parse_args()

    try:
        if args.transport == "stdio":
            success = asyncio.run(test_all_tools_stdio(skip_scans=args.skip_scans))
        else:
            success = asyncio.run(test_all_tools_http(args.url, skip_scans=args.skip_scans))

        if success:
            print("\n✓ All tests passed!")
            return 0
        else:
            print("\n✗ Some tests failed")
            return 1

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        import traceback

        print(f"\n✗ Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
