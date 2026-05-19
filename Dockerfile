# Use the official Python slim image for a smaller footprint
FROM python:3.11-slim

# Set environment variables to ensure Python output is unbuffered (essential for real-time logging)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install C-compiler dependencies required for py-radix
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create a non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Create the RPKI data directory and set permissions
# This ensures the user can access the volume mount point
RUN mkdir -p /data/rpki && \
    chown -R appuser:appgroup /app /data/rpki

# Switch to the non-root user
USER appuser

# Run the monitoring engine
CMD ["python", "main.py"]
