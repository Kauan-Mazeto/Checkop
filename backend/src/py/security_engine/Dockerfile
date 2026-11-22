# Motor de segurança (FastAPI) com as ferramentas de varredura já instaladas:
# Nuclei + templates, Subfinder, Gitleaks e Semgrep. Mesmas versões do desenvolvimento.
FROM python:3.13-slim

ARG NUCLEI_VERSION=3.11.1
ARG SUBFINDER_VERSION=2.17.0
ARG GITLEAKS_VERSION=8.30.1
# preenchido pelo Docker (amd64 no Windows/Intel, arm64 nos Macs M1+)
ARG TARGETARCH=amd64

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH}"; \
    gitleaks_arch="$([ "$arch" = "arm64" ] && echo arm64 || echo x64)"; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    curl -fsSL -o /tmp/subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip"; \
    unzip -o /tmp/subfinder.zip subfinder -d /usr/local/bin; \
    curl -fsSL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz"; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/gitleaks; \
    rm -f /tmp/nuclei.zip /tmp/subfinder.zip /tmp/gitleaks.tgz

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# roda sem root; os templates do Nuclei ficam no home deste usuário
RUN useradd --create-home --uid 10001 checkop
COPY --chown=checkop:checkop app ./app
USER checkop
# ~14 mil templates já na imagem (o backend atualiza a cada 24 h pelo /templates/update)
RUN nuclei -update-templates -silent || echo "templates do Nuclei: baixe depois com POST /templates/update"

EXPOSE 8010
HEALTHCHECK --interval=10s --timeout=5s --retries=12 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health', timeout=3)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
