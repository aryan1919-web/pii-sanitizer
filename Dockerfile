# ── Hugging Face Spaces Docker Image ──────────────────────────
# SDK: docker | Port: 7860
# Build: ~10 min first time (model downloads cached after)
# ──────────────────────────────────────────────────────────────

FROM python:3.10-slim

# System dependencies for OpenCV, PDF processing, and image handling
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    poppler-utils \
    libmagic1 \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (required by HF Spaces)
RUN useradd -m -u 1000 user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR /app

# Install Python dependencies (CPU-only torch to save ~1.5GB)
COPY requirements-hf.txt .
RUN pip install --no-cache-dir -r requirements-hf.txt && \
    python -m spacy download en_core_web_sm

# Copy application code
COPY . .

# Ensure upload directories exist and are writable
RUN mkdir -p uploads/raw uploads/sanitized ocr_outputs && \
    chown -R user:user /app

USER user

# HF Spaces expects port 7860
EXPOSE 7860

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
