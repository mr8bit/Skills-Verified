FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e ".[llm]" \
    && pip install --no-cache-dir bandit semgrep pip-audit

RUN mkdir -p /workspace /reports
VOLUME ["/workspace", "/reports"]

ENTRYPOINT ["skills-verified"]
CMD ["--help"]
