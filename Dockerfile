ARG PLAYWRIGHT_TAG=v1.49.0-jammy
FROM mcr.microsoft.com/playwright/python:${PLAYWRIGHT_TAG}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Tor for --tor flag; rest of the browser deps ship with the base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir \
        "fastapi>=0.115" "uvicorn[standard]>=0.32" "pydantic>=2" \
        "aiohttp-socks>=0.8" "playwright>=1.49" \
        "holehe>=1.61" "httpx>=0.24"

# Playwright browsers are preinstalled in the base image; reinstall only if
# the pip upgrade above changed the pinned Playwright major version.
RUN playwright install --with-deps chromium || true

COPY . .

RUN useradd --create-home --uid 1000 osint \
    && mkdir -p /data /home/osint/.local/share/open-source-intelligence \
    && chown -R osint:osint /app /data /home/osint
USER osint

VOLUME ["/data", "/home/osint/.local/share/open-source-intelligence"]
EXPOSE 8000

ENTRYPOINT ["python", "-m", "uvicorn", "core.api.server:build_app", "--factory"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
