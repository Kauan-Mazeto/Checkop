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
     Url  = 'https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip' }
)

foreach ($d in $downloads) {
  $target = Join-Path $tools $d.Name
  if (Test-Path (Join-Path $tools $d.Check)) {
    Write-Host "[ok] $($d.Name) já está instalado" -ForegroundColor Green
    continue
  }
  Write-Host "[..] baixando $($d.Name)..." -ForegroundColor Cyan
  New-Item -ItemType Directory -Force $target | Out-Null
  $zip = Join-Path $target 'download.zip'
  Invoke-WebRequest -Uri $d.Url -OutFile $zip -UseBasicParsing
  Expand-Archive -Path $zip -DestinationPath $target -Force
  Remove-Item $zip
  if (-not (Test-Path (Join-Path $tools $d.Check))) { throw "Não encontrei $($d.Check) depois de extrair $($d.Name)." }
  Write-Host "[ok] $($d.Name) instalado" -ForegroundColor Green
}

# Templates do Nuclei (~14 mil, ficam em %USERPROFILE%\nuclei-templates)
Write-Host "[..] baixando/atualizando os templates do Nuclei..." -ForegroundColor Cyan
& (Join-Path $tools 'nuclei\nuclei.exe') -update-templates -silent
Write-Host "[ok] templates do Nuclei prontos" -ForegroundColor Green

# Semgrep (análise de código) vem pelo pip: requirements.txt do motor
Write-Host ""
Write-Host "Ferramentas prontas em $tools" -ForegroundColor Green
Write-Host "Próximo passo: instalar as dependências Python do motor (veja o SETUP.md)."
