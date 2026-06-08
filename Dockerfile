# REST scanner host for the OpenAI GPT Action.
#
# Serves extensions/claude_mcp/server.py (FastAPI) so a Custom GPT Action can call
# /check_package, /sast_scan, /sca_scan, /full_scan over HTTPS. The MCP stdio server
# (mcp_server.py) is NOT used here, so the `mcp` SDK is intentionally not installed.
FROM python:3.12-slim

WORKDIR /app

# REST-only dependencies (subset of extensions/claude_mcp/requirements.txt).
RUN pip install --no-cache-dir \
    "fastapi>=0.110" \
    "uvicorn[standard]>=0.29" \
    "requests>=2.31" \
    "pydantic>=2.0"

# Copy just the package the REST server imports (server.py -> rules.py, registry.py).
COPY extensions/__init__.py extensions/__init__.py
COPY extensions/claude_mcp/ extensions/claude_mcp/

# Render (and most PaaS) inject $PORT; default to 8765 for local `docker run`.
ENV PORT=8765
EXPOSE 8765

# Drop privileges — run as a non-root user.
RUN useradd --create-home --uid 10001 appuser
USER appuser

# Shell form so $PORT expands at runtime.
CMD ["sh", "-c", "uvicorn extensions.claude_mcp.server:app --host 0.0.0.0 --port ${PORT:-8765}"]
