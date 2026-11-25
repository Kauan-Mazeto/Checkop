# Baixa as ferramentas de varredura do Checkop para backend\tools\ (pasta fora do git).
# Mesmas versões usadas no desenvolvimento. Pode rodar de novo: o que já existe é pulado.
#
# Uso (na raiz do projeto):
#   powershell -ExecutionPolicy Bypass -File scripts\baixar-ferramentas.ps1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # sem isso o download no PowerShell 5.1 fica muito lento
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root  = Split-Path $PSScriptRoot -Parent
$tools = Join-Path $root 'backend\tools'
New-Item -ItemType Directory -Force $tools | Out-Null

$downloads = @(
  @{ Name = 'nuclei';    Check = 'nuclei\nuclei.exe';
     Url  = 'https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip' },
  @{ Name = 'subfinder'; Check = 'subfinder\subfinder.exe';
     Url  = 'https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_windows_amd64.zip' },
  @{ Name = 'gitleaks';  Check = 'gitleaks\gitleaks.exe';
     Url  = 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip' },
  @{ Name = 'zap';       Check = 'zap\ZAP_2.17.0\zap.bat';
     Url  = 'https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip' },
  # ---------- análise de código ----------
  @{ Name = 'shellcheck'; Check = 'shellcheck\shellcheck.exe';
     Url  = 'https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.zip' },
  @{ Name = 'actionlint'; Check = 'actionlint\actionlint.exe';
     Url  = 'https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_windows_amd64.zip' },
  @{ Name = 'pmd';        Check = 'pmd\pmd-bin-7.29.0\bin\pmd.bat';
     Url  = 'https://github.com/pmd/pmd/releases/download/pmd_releases%2F7.29.0/pmd-dist-7.29.0-bin.zip' },
  # executáveis avulsos (sem zip)
  @{ Name = 'osv-scanner'; Check = 'osv-scanner\osv-scanner.exe'; Exe = $true;
     Url  = 'https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_windows_amd64.exe' },
  @{ Name = 'hadolint';    Check = 'hadolint\hadolint.exe'; Exe = $true;
     Url  = 'https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-windows-x86_64.exe' }
)

foreach ($d in $downloads) {
  $target = Join-Path $tools $d.Name
  # ZAP já instalado pelo instalador do Windows (pasta "ZAP\Zed Attack Proxy") também vale
  $zapPronto = $d.Name -eq 'zap' -and (Get-ChildItem $target -Recurse -Filter 'zap.bat' -ErrorAction SilentlyContinue | Select-Object -First 1)
  if ($zapPronto -or (Test-Path (Join-Path $tools $d.Check))) {
    Write-Host "[ok] $($d.Name) já está instalado" -ForegroundColor Green
    continue
  }
  Write-Host "[..] baixando $($d.Name)..." -ForegroundColor Cyan
  New-Item -ItemType Directory -Force $target | Out-Null
  if ($d.Exe) {
    Invoke-WebRequest -Uri $d.Url -OutFile (Join-Path $tools $d.Check) -UseBasicParsing
  } else {
    $zip = Join-Path $target 'download.zip'
    Invoke-WebRequest -Uri $d.Url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $target -Force
    Remove-Item $zip
  }
  if (-not (Test-Path (Join-Path $tools $d.Check))) { throw "Não encontrei $($d.Check) depois de extrair $($d.Name)." }
  Write-Host "[ok] $($d.Name) instalado" -ForegroundColor Green
}

# Templates do Nuclei (~14 mil, ficam em %USERPROFILE%\nuclei-templates)
Write-Host "[..] baixando/atualizando os templates do Nuclei..." -ForegroundColor Cyan
& (Join-Path $tools 'nuclei\nuclei.exe') -update-templates -silent
Write-Host "[ok] templates do Nuclei prontos" -ForegroundColor Green

# ---------- análise de código: ferramentas Python (ambiente separado) ----------
# Ficam num venv próprio para não mexer nas dependências do Semgrep (Checkov traz muitas).
$py = Join-Path $tools 'pyanalyzers'
# no Windows o pip instala o Checkov como checkov.cmd (não .exe)
if (-not (Test-Path (Join-Path $py 'Lib\site-packages\checkov'))) {
  Write-Host "[..] instalando Ruff, Bandit, Flawfinder, yamllint e Checkov (alguns minutos)..." -ForegroundColor Cyan
  if (-not (Test-Path (Join-Path $py 'Scripts\python.exe'))) { python -m venv $py }
  & (Join-Path $py 'Scripts\python.exe') -m pip install --quiet --upgrade pip
  & (Join-Path $py 'Scripts\python.exe') -m pip install --quiet ruff==0.17.6 bandit==1.9.4 flawfinder==2.0.20 yamllint==1.38.0 checkov==3.4.7
}
Write-Host "[ok] Ruff, Bandit, Flawfinder, yamllint e Checkov" -ForegroundColor Green

# ---------- análise de código: ESLint (+ segurança, TypeScript) e HTMLHint ----------
$js = Join-Path $tools 'js-analyzers'
if (-not (Test-Path (Join-Path $js 'node_modules\eslint'))) {
  Write-Host "[..] instalando ESLint, TypeScript e HTMLHint..." -ForegroundColor Cyan
  New-Item -ItemType Directory -Force $js | Out-Null
  Copy-Item (Join-Path $root 'backend\src\py\security_engine\app\analyzers\js\package.json') $js -Force
  Push-Location $js
  npm install --no-audit --no-fund --omit=dev --loglevel=error
  Pop-Location
}
Write-Host "[ok] ESLint, TypeScript e HTMLHint" -ForegroundColor Green

# PMD (Java/Apex) precisa do Java instalado (o mesmo do ZAP).
# cppcheck (C/C++): o oficial para Windows é um .msi; extrai os arquivos em tools\cppcheck
# (instalação administrativa: não instala nada no sistema nem pede admin)
$cpp = Join-Path $tools 'cppcheck'
if (-not (Get-ChildItem $cpp -Recurse -Filter cppcheck.exe -ErrorAction SilentlyContinue)) {
  Write-Host "[..] baixando o cppcheck..." -ForegroundColor Cyan
  New-Item -ItemType Directory -Force $cpp | Out-Null
  $msi = Join-Path $env:TEMP 'cppcheck-2.22.0-x64-Setup.msi'
  Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/cppcheck-opensource/cppcheck/releases/download/2.22.0/cppcheck-2.22.0-x64-Setup.msi' -OutFile $msi
  Start-Process msiexec.exe -ArgumentList @('/a', "`"$msi`"", '/qn', "TARGETDIR=`"$cpp`"") -Wait
  Remove-Item $msi, (Join-Path $cpp '*.msi') -Force -ErrorAction SilentlyContinue
}
Write-Host "[ok] cppcheck" -ForegroundColor Green

# Semgrep (análise de código) vem pelo pip: requirements.txt do motor
Write-Host ""
Write-Host "Ferramentas prontas em $tools" -ForegroundColor Green
Write-Host "Próximo passo: instalar as dependências Python do motor (veja o SETUP.md)."
