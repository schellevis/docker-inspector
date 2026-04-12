FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml ./

# Create a minimal uv.lock by syncing (generates lock if absent)
RUN uv sync --no-dev

# Copy application code
COPY app/ ./app/

# Create a non-root user; add to group 999 (common docker socket group)
# The GID can be overridden at runtime with --group-add if needed.
RUN groupadd -g 999 docker 2>/dev/null || true && \
    useradd -m -u 1000 -G docker scanner

# Ensure the data directory exists with correct permissions
RUN mkdir -p /data && chown scanner:scanner /data

USER scanner

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
