FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    tcpdump \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY backend/requirements.txt /app/backend/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy application code
COPY backend/ /app/backend/
COPY data/ /app/data/

# Create necessary directories
RUN mkdir -p /app/data/pcap /app/data/reports

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Run the application
CMD ["python", "backend/app.py"]
