FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install curl for downloading Tailwind CLI
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Download Tailwind CSS standalone CLI (no Node.js needed)
RUN curl -sL https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64 \
    -o /usr/local/bin/tailwindcss && chmod +x /usr/local/bin/tailwindcss

# Copy requirements first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and entrypoint
COPY tailwind.config.js ./
COPY docker-entrypoint.sh ./
COPY src ./src
COPY scripts ./scripts
COPY pyproject.toml ./

# Build production CSS (scans templates, outputs minified CSS)
RUN tailwindcss -i src/authmcp_gateway/static/input.css \
    -o src/authmcp_gateway/static/tailwind.css --minify

# Install package
RUN pip install --no-cache-dir -e .

# Create data directory and logs
RUN mkdir -p /app/data /app/data/logs

# Expose port
EXPOSE 8000

# Set environment
ARG GIT_COMMIT=unknown
ENV PYTHONUNBUFFERED=1
ENV GIT_COMMIT=$GIT_COMMIT

# Entrypoint rebuilds CSS at startup (handles volume-mounted src)
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["authmcp-gateway", "start", "--host", "0.0.0.0", "--port", "8000"]
