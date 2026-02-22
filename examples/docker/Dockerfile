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

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/
# Dataset is large and mounted at runtime, so we don't copy it into the image
# COPY dataset/ ./dataset/
COPY scripts/ ./scripts/

# Copy pre-downloaded models to the default cache location
# RapidOCR (torch) looks in ~/.cache/RapidOCR by default
COPY models/ /root/.cache/RapidOCR/

# Install the package and its dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Ensure models are in the site-packages directory where RapidOCR (torch) expects them
# This handles the case where it ignores the user cache
RUN python -c "import sys, shutil, os, site; \
    src = '/root/.cache/RapidOCR'; \
    # The log indicates direct usage of 'rapidocr' package dir \
    dest_candidates = [ \
        os.path.join(site.getsitepackages()[0], 'rapidocr', 'models'), \
        os.path.join(site.getsitepackages()[0], 'rapidocr_torch', 'models'), \
    ]; \
    dest = dest_candidates[0]; \
    print(f'Copying models from {src} to {dest}...'); \
    os.makedirs(dest, exist_ok=True); \
    shutil.copytree(src, dest, dirs_exist_ok=True)"

# Set the entrypoint to the CLI
ENTRYPOINT ["doc-firewall"]

# Default command (show help)
CMD ["--help"]
