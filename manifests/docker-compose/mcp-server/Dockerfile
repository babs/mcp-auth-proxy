# Demo MCP server — minimal image for the hello-world FastMCP service.
# Not intended for production: no non-root user, no hardened base image.
FROM python:3.12-slim

# >=1.9.0 for the streamable-http transport; <2 because mcp 2.0.0
# removes the mcp.server.fastmcp module server.py imports.
RUN pip install --no-cache-dir "mcp[cli]>=1.9.0,<2"

WORKDIR /app
COPY server.py .

# FastMCP binds on 8000 by default (see FastMCP(host=..., port=...)).
EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["python", "server.py"]
