# Demo MCP server — minimal image for the hello-world FastMCP service.
# Not intended for production: no non-root user, no hardened base image.
FROM python:3.12-slim

# Pin a version range so the streamable-http transport is available.
RUN pip install --no-cache-dir "mcp[cli]>=1.9.0"

WORKDIR /app
COPY server.py .

# FastMCP binds on 8000 by default (see FastMCP(host=..., port=...)).
EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["python", "server.py"]
