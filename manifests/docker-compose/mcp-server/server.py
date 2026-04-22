"""Demo hello-world MCP server — Streamable HTTP transport.

Three toy tools (hello, add, echo) to verify end-to-end auth through the proxy.
FastMCP ≥ 1.9.0 is required for the streamable-http transport.
"""
from mcp.server.fastmcp import FastMCP

# Bind on all interfaces so the container is reachable by the proxy service.
mcp = FastMCP("hello-world-demo", host="0.0.0.0", port=8000)


@mcp.tool()
def hello(name: str = "world") -> str:
    """Greet someone."""
    return f"Hello, {name}! I am a demo MCP server secured by mcp-auth-proxy."


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the result."""
    return a + b


@mcp.tool()
def echo(message: str) -> str:
    """Echo a message back to the caller."""
    return message


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
