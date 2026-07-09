# TQSC v2.0 — Base image
# Multi-stage: build deps first, then runtime
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir maturin

# Copy Rust code and build native module
COPY tqsc-native/ /build/tqsc-native/
RUN cd tqsc-native && maturin build --release --out /build/wheels

# ── Runtime image ──
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install system deps for psutil + networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd curl procps && \
    rm -rf /var/lib/apt/lists/*

# Copy Python deps + native wheels
COPY --from=builder /build/wheels/ /tmp/wheels/
RUN pip install --no-cache-dir /tmp/wheels/*.whl && \
    pip install --no-cache-dir psutil cryptography geopy pynacl && \
    rm -rf /tmp/wheels

# Copy TQSC source
COPY tqsc/ /app/tqsc/
COPY run.py /app/

ENV PYTHONPATH=/app
ENV TQSC_HOME=/app/data

# Default: run supervisor
CMD ["python", "run.py", "--supervised"]
