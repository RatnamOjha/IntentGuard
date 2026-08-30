FROM openpolicyagent/opa:1.19.1-static AS opa

FROM python:3.11.13-slim-bookworm AS runtime

# The Python base image ships wheel system-wide, where image scanners see it.
# Keep that copy above the version patched for CVE-2026-24049.
ARG WHEEL_VERSION=0.48.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/intentguard/.venv/bin:${PATH}"

RUN groupadd --system intentguard \
    && useradd --system --gid intentguard --home-dir /opt/intentguard intentguard

WORKDIR /opt/intentguard
COPY --from=opa /opa /usr/local/bin/opa
COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies
COPY migrations ./migrations
COPY scripts/migrate.py scripts/seed_demo.py ./scripts/
RUN python -m pip install --no-cache-dir --upgrade "wheel==${WHEEL_VERSION}" \
    && python -m venv .venv \
    && .venv/bin/pip install --no-cache-dir ".[api,postgres,agent]"

USER intentguard
EXPOSE 8000 8100
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"]

CMD ["uvicorn", "intentguard.api:app", "--host", "0.0.0.0", "--port", "8000"]
