# Use Python 3.10 slim image for smaller size
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Environment variables to disable OCR and prevent model downloads
ENV DOCLING_DISABLE_OCR=1
ENV RAPIDOCR_DISABLE_AUTO_DOWNLOAD=1

# Install system dependencies that might be needed by docling and document processing
# Also installing ClamAV for antivirus scanning capability
RUN apt-get update && apt-get install -y \
    libmagic1 \
    libglib2.0-0 \
    libgl1 \
    libgomp1 \
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

# Update ClamAV definitions (this might take a minute during build)
# We accept the overhead here to ensure the image is "ready to scan"
RUN freshclam || true

# Install the package from PyPI
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir doc-firewall

# Models will be downloaded on first run or can be pre-cached here if needed
# ENV RAPIDOCR_DISABLE_AUTO_DOWNLOAD=0

# Set the entrypoint to the CLI
ENTRYPOINT ["doc-firewall"]

# Default command (show help)
CMD ["--help"]
