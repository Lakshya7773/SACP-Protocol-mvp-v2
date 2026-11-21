# Multi-stage Dockerfile for Sovereign Agentic Context Protocol (SACP)
# Base: Python 3.12 Slim on Debian Bookworm
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies into wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt

# ==============================================================================
# Final Runtime Container
# ==============================================================================
FROM python:3.12-slim AS runtime

# Create non-root user for sovereign zero-trust isolation
RUN groupadd -g 1001 sacp && \
    useradd -u 1001 -g sacp -m -s /bin/bash appuser

WORKDIR /app

# Copy and install pre-built wheels from builder
COPY --from=builder /build/wheels /wheels
COPY --from=builder /build/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir /wheels/* && \
    rm -rf /wheels

# Copy application code
COPY --chown=appuser:sacp app/ ./app/
COPY --chown=appuser:sacp .env.example ./.env.example

# Set environment variables for ephemeral in-RAM execution
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    HOST=0.0.0.0

# Switch to unprivileged non-root user
USER appuser

EXPOSE 8000

# Run single-worker Uvicorn instance to maintain RAM hygiene and thread-safe hash-chain consistency
CMD ["python", "-m", "app.mcp_server.server"]
