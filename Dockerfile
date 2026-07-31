# TQSC v2.0 — Docker producción
FROM python:3.11-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
    -r requirements.txt \
    scikit-learn joblib numpy

FROM python:3.11-slim
# Usuario no-root
RUN groupadd -r tqsc && useradd -r -g tqsc -d /app -s /sbin/nologin tqsc

# Solo lo necesario: tini (señales) + curl (healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl tini && rm -rf /var/lib/apt/lists/*

# Python deps compiladas
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

WORKDIR /app
COPY tqsc/ /app/tqsc/
COPY run.py /app/

# Data dir con permisos para tqsc
RUN mkdir -p /app/data && chown -R tqsc:tqsc /app

ENV PYTHONPATH=/app \
    TQSC_HOME=/app/data \
    TQSC_DOCKER=1

VOLUME /app/data
EXPOSE 9090 2222

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:9090/api > /dev/null 2>&1 || exit 1

USER tqsc
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "run.py", "--hud"]
