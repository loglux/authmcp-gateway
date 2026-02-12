FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src ./src
COPY scripts ./scripts
COPY pyproject.toml ./

# Install package
RUN pip install --no-cache-dir -e .

# Create data directory and logs
RUN mkdir -p /app/data /app/data/logs

# Expose port
EXPOSE 8000

# Set environment
ENV PYTHONUNBUFFERED=1

# Run application
CMD ["authmcp-gateway", "start", "--host", "0.0.0.0", "--port", "8000"]
