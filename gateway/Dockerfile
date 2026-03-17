FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl jq openssh-client \
    && rm -rf /var/lib/apt/lists/*

# SSH setup — entrypoint copies keys with correct permissions
RUN mkdir -p /root/.ssh

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

# Copy project files and install deps
COPY pyproject.toml .
RUN uv sync --no-dev --no-install-project

# Copy source as gateway package
COPY __init__.py ./gateway/
COPY audit.py policy.py auth.py main.py ./gateway/
COPY routes/ ./gateway/routes/
COPY templates/ ./gateway/templates/

# Create data directory for audit.db
RUN mkdir -p /data

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uv", "run", "uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "9000"]
