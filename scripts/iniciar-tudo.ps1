# Sobe o ambiente local do Checkop, cada serviço numa janela própria:
#   ZAP (8091) · motor Python (8010) · backend (8080) · front (4200) · laboratório (3000)
# Serviço que já está rodando (porta ocupada) é pulado, em vez de abrir uma cópia que dá erro.
# No fim espera tudo responder e abre o navegador.
#
# Uso (na raiz do projeto): dois cliques em iniciar.cmd, ou
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar-tudo.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar-tudo.ps1 -SemLab        (sem o alvo de teste)
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar-tudo.ps1 -SemNavegador  (não abre o navegador)
# Para fechar tudo: parar.cmd (ou scripts\parar-tudo.ps1)

param([switch]$SemLab, [switch]$SemNavegador)

$ErrorActionPreference = 'Stop'
$root    = Split-Path $PSScriptRoot -Parent
$backend = Join-Path $root 'backend'
$envFile = Join-Path $backend '.env'

if (-not (Test-Path $envFile)) { throw "Falta o backend\.env (copie o backend\.env.example e preencha)." }

$keyLine = Select-String $envFile -Pattern '^\s*ZAP_API_KEY\s*=\s*(.*)$' | Select-Object -First 1
$key = if ($keyLine) { $keyLine.Matches[0].Groups[1].Value.Trim().Trim('"') } else { '' }
if (-not $key) { throw "ZAP_API_KEY está vazio no backend\.env." }

function Test-Porta([int]$porta) {
  [bool](Get-NetTCPConnection -LocalPort $porta -State Listen -ErrorAction SilentlyContinue)
}

function Abrir($titulo, $porta, $pasta, $comando) {
  if (Test-Porta $porta) {
    Write-Host "[ja rodando] $titulo" -ForegroundColor DarkGray
    return
  }
  $cmd = "`$Host.UI.RawUI.WindowTitle = '$titulo'; Set-Location -LiteralPath '$pasta'; $comando"
  Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmd
  Write-Host "[abrindo]    $titulo" -ForegroundColor Cyan
}

# ZAP: o baixado pelo scripts\baixar-ferramentas.ps1 (backend\tools\zap) ou o do instalador do Windows
$zapBat = Get-ChildItem (Join-Path $backend 'tools\zap') -Recurse -Filter 'zap.bat' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $zapBat) {
  $zapBat = @("$env:ProgramFiles\ZAP\Zed Attack Proxy\zap.bat", "${env:ProgramFiles(x86)}\ZAP\Zed Attack Proxy\zap.bat") |
    Where-Object { $_ -and (Test-Path $_) } | ForEach-Object { Get-Item $_ } | Select-Object -First 1
}
if (-not $zapBat) { throw "ZAP não encontrado (nem em backend\tools\zap nem em Arquivos de Programas). Rode scripts\baixar-ferramentas.ps1." }

Abrir 'ZAP :8091'     8091 $zapBat.DirectoryName                         "& '.\zap.bat' -daemon -host 127.0.0.1 -port 8091 -config api.key=$key"
Abrir 'Motor :8010'   8010 (Join-Path $backend 'src\py\security_engine') 'python -m uvicorn app.main:app --host 127.0.0.1 --port 8010'
Abrir 'Backend :8080' 8080 $backend                                      'npm start'
Abrir 'Front :4200'   4200 (Join-Path $root 'front-end')                 'npx ng serve'
if (-not $SemLab) {
  Abrir 'Lab :3000'   3000 (Join-Path $backend 'lab')                    'node lab-vulneravel.mjs'
}

# espera cada serviço responder (o ZAP é o mais lento: 15-60 s)
$servicos = [ordered]@{ 'Motor' = 8010; 'Backend' = 8080; 'Front' = 4200; 'ZAP' = 8091 }
if (-not $SemLab) { $servicos['Lab'] = 3000 }
Write-Host ''
Write-Host 'Esperando os serviços subirem...' -ForegroundColor Cyan
$limite = (Get-Date).AddMinutes(3)
$pendentes = [System.Collections.ArrayList]@($servicos.Keys)
while ($pendentes.Count -gt 0 -and (Get-Date) -lt $limite) {
  foreach ($nome in @($pendentes)) {
    if (Test-Porta $servicos[$nome]) {
      Write-Host "[ok] $nome (:$($servicos[$nome]))" -ForegroundColor Green
      $pendentes.Remove($nome)
    }
  }
  if ($pendentes.Count -gt 0) { Start-Sleep -Seconds 2 }
}
foreach ($nome in $pendentes) {
  Write-Host "[!]  $nome não respondeu em 3 min: veja a janela '$nome' para o erro." -ForegroundColor Yellow
}

if (-not $SemNavegador -and (Test-Porta 4200)) {
  Start-Process 'http://localhost:4200'
}
Write-Host ''
Write-Host 'Pronto: http://localhost:4200  (para fechar tudo: parar.cmd)' -ForegroundColor Green
