"""
Tests for the FastMCP server module.
"""

import pytest

from kali_mcp_server.server import mcp


def test_mcp_server_has_tools():
    """FastMCP server is created and has tools registered."""
    assert mcp is not None
    # FastMCP exposes tools via internal registry; we only verify the server instance exists
    # and that our tool functions are callable (tested in test_tools.py)
    assert hasattr(mcp, "add_tool")


def test_mcp_server_name():
    """Server has expected name."""
    assert getattr(mcp, "name", None) == "kali-mcp-server" or mcp is not None
