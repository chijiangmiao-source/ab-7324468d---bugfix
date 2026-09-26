# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SEAL_HOST=0.0.0.0 \
    SEAL_PORT=8080 \
    SEAL_DB=/data/seal.db

WORKDIR /srv

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY app ./app
COPY scripts ./scripts
COPY tests ./tests
COPY conftest.py ./conftest.py

RUN useradd --system --uid 10001 seal \
    && mkdir -p /data \
    && chown -R seal:seal /data /srv
USER seal

VOLUME ["/data"]
EXPOSE 8080

# Container health check: the same probe compose waits on.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
    CMD ["python", "-c", "import os,urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('SEAL_PORT','8080')+'/healthz',timeout=2).status==200 else 1)"]

# Default: run the seal server. The compose `verify` service overrides the
# command with `python scripts/verify.py`.
CMD ["python", "-m", "app"]
