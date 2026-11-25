# Motor de segurança (FastAPI) com as ferramentas já instaladas:
#   varredura web     Nuclei (+ templates), Subfinder
#   análise de código Semgrep, Gitleaks, Ruff, Bandit, ESLint (+ security, TypeScript), HTMLHint,
#                     Flawfinder, cppcheck, ShellCheck, Hadolint, yamllint, actionlint, Checkov,
#                     PMD (Java/Apex) e OSV-Scanner (dependências)
FROM python:3.13-slim

ARG NUCLEI_VERSION=3.11.1
ARG SUBFINDER_VERSION=2.17.0
ARG GITLEAKS_VERSION=8.30.1
ARG HADOLINT_VERSION=2.15.1
ARG OSV_VERSION=2.7.1
ARG ACTIONLINT_VERSION=1.7.12
ARG PMD_VERSION=7.29.0
# preenchido pelo Docker (amd64 no Windows/Intel, arm64 nos Macs M1+)
ARG TARGETARCH=amd64

# shellcheck e cppcheck pelo apt; Node (ESLint/HTMLHint/TypeScript) e o JDK (PMD + javac) também
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip shellcheck cppcheck nodejs npm default-jdk-headless \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH}"; \
    x64="$([ "$arch" = "arm64" ] && echo arm64 || echo x64)"; \
    x86_64="$([ "$arch" = "arm64" ] && echo arm64 || echo x86_64)"; \
    cd /tmp; \
    curl -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
    unzip -o nuclei.zip nuclei -d /usr/local/bin; \
    curl -fsSL -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip"; \
    unzip -o subfinder.zip subfinder -d /usr/local/bin; \
    curl -fsSL -o gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${x64}.tar.gz"; \
    tar -xzf gitleaks.tgz -C /usr/local/bin gitleaks; \
    curl -fsSL -o /usr/local/bin/hadolint "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-${x86_64}"; \
    curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${arch}"; \
    curl -fsSL -o actionlint.tgz "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${arch}.tar.gz"; \
    tar -xzf actionlint.tgz -C /usr/local/bin actionlint; \
    curl -fsSL -o pmd.zip "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-dist-${PMD_VERSION}-bin.zip"; \
    unzip -q pmd.zip -d /opt; \
    ln -s "/opt/pmd-bin-${PMD_VERSION}/bin/pmd" /usr/local/bin/pmd; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/gitleaks /usr/local/bin/hadolint \
             /usr/local/bin/osv-scanner /usr/local/bin/actionlint; \
    rm -f /tmp/*.zip /tmp/*.tgz

# ferramentas Python de análise num ambiente separado: o Checkov traz muitas
# dependências e não pode mexer nas do Semgrep
RUN python -m venv /opt/pyanalyzers \
 && /opt/pyanalyzers/bin/pip install --no-cache-dir \
      ruff==0.17.6 bandit==1.9.4 flawfinder==2.0.20 yamllint==1.38.0 checkov==3.4.7 \
 && for tool in ruff bandit flawfinder yamllint checkov; do ln -s "/opt/pyanalyzers/bin/$tool" "/usr/local/bin/$tool"; done

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ESLint (+ plugin security, TypeScript) e HTMLHint, nas versões fixadas no package.json
COPY app/analyzers/js/package.json /opt/js-analyzers/package.json
RUN cd /opt/js-analyzers && npm install --no-audit --no-fund --omit=dev --loglevel=error
ENV JS_ANALYZERS_DIR=/opt/js-analyzers

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
