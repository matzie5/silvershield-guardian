# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /workspace

RUN pip install --no-cache-dir uv>=0.5.0

COPY pyproject.toml README.md ./
COPY app ./app

RUN uv venv /opt/venv && \
    VIRTUAL_ENV=/opt/venv uv pip install --no-cache ".[gcp]"

FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    LOG_FORMAT=json \
    OTEL_SDK_DISABLED=false

RUN groupadd --gid 10001 silvershield && \
    useradd --uid 10001 --gid silvershield --create-home --shell /usr/sbin/nologin silvershield

WORKDIR /home/silvershield/service

COPY --from=builder /opt/venv /opt/venv
COPY --chown=silvershield:silvershield app ./app
COPY --chown=silvershield:silvershield pyproject.toml README.md ./

RUN mkdir -p /home/silvershield/service/data && \
    chown -R silvershield:silvershield /home/silvershield/service/data

USER silvershield

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "app.fast_api_app:fast_api_app", "--host", "0.0.0.0", "--port", "8080"]
