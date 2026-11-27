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

# Só um ZAP pode usar a pasta %USERPROFILE%\ZAP. Um ZAP que sobrou de outra execução
# (travado antes de abrir a porta, ou o ZAP com janela aberto à mão) faz o novo morrer na hora.
if (-not (Test-Porta 8091)) {
  Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe' OR Name='ZAP.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq 'ZAP.exe' -or $_.CommandLine -match 'zap-[\d.]+\.jar' } |
    ForEach-Object {
      Write-Host "[fechando]   ZAP antigo que estava preso (pid $($_.ProcessId))" -ForegroundColor DarkYellow
      & taskkill /PID $_.ProcessId /T /F | Out-Null
    }
}

# a saída do ZAP também vai para um arquivo, para mostrar o erro aqui se ele não subir
$zapSaida = Join-Path $env:TEMP 'checkop-zap.log'
Remove-Item $zapSaida -ErrorAction SilentlyContinue
Abrir 'ZAP :8091'     8091 $zapBat.DirectoryName                         "& '.\zap.bat' -daemon -host 127.0.0.1 -port 8091 -config api.key=$key 2>&1 | Out-String -Stream | Tee-Object -FilePath '$zapSaida'"
# ---------- motor Python ----------
# Já falhou "sem motivo" (a janela fechava o erro de vista). Agora: Python certo (não o
# atalho da Microsoft Store), teste de importação antes, log em arquivo e nova tentativa.
$motorPasta = Join-Path $backend 'src\py\security_engine'
$motorSaida = Join-Path $env:TEMP 'checkop-motor.log'
$python = (Get-Command python -All -ErrorAction SilentlyContinue |
  Where-Object { $_.Source -notmatch 'WindowsApps' } | Select-Object -First 1).Source
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $python) { throw "Python não encontrado no PATH (instale o Python 3.13 marcando 'Add python.exe to PATH')." }

# a porta 8010 pode cair numa faixa que o Windows (Hyper-V/WSL/Docker) reserva a cada boot
$reservadas = netsh interface ipv4 show excludedportrange protocol=tcp 2>$null |
  ForEach-Object { if ($_ -match '^\s*(\d+)\s+(\d+)') { ,@([int]$Matches[1], [int]$Matches[2]) } }
if ($reservadas | Where-Object { 8010 -ge $_[0] -and 8010 -le $_[1] }) {
  Write-Host '[!]  A porta 8010 está reservada pelo Windows neste boot; o motor não vai conseguir abri-la.' -ForegroundColor Yellow
  Write-Host '     Resolva num PowerShell como administrador:  net stop winnat ; net start winnat' -ForegroundColor Yellow
}

# teste rápido: erro de código ou dependência faltando aparece aqui, não numa janela perdida
if (-not (Test-Porta 8010)) {
  $teste = & {
    $ErrorActionPreference = 'Continue'
    Push-Location -LiteralPath $motorPasta
    try { & $python -c 'import app.main' 2>&1 | Out-String } finally { Pop-Location }
  }
  if ($LASTEXITCODE -ne 0) {
    Write-Host '[!]  O motor não carrega. Erro:' -ForegroundColor Red
    $teste.Trim() -split "`n" | Select-Object -Last 12 | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkYellow }
    Write-Host '     Se for "No module named ...":  cd backend\src\py\security_engine ; python -m pip install -r requirements.txt' -ForegroundColor Yellow
  }
}

$motorComando = "& '$python' -m uvicorn app.main:app --host 127.0.0.1 --port 8010 2>&1 | Out-String -Stream | Tee-Object -FilePath '$motorSaida'"
function Abrir-Motor {
  Remove-Item $motorSaida -ErrorAction SilentlyContinue
  Abrir 'Motor :8010' 8010 $motorPasta $motorComando
}
function Motor-Vivo {
  [bool](Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='py.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'uvicorn app\.main' })
}
Abrir-Motor
$motorTentativas = 1
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
  # o motor sobe em segundos; se o processo morreu, tenta de novo uma vez
  if ($pendentes -contains 'Motor' -and $motorTentativas -lt 2 -and ((Get-Date) -gt $limite.AddMinutes(-2.5)) -and -not (Motor-Vivo)) {
    Write-Host '[!]  O motor caiu ao iniciar; abrindo de novo...' -ForegroundColor Yellow
    if (Test-Path $motorSaida) { Get-Content $motorSaida -Tail 8 | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkYellow } }
    Abrir-Motor
    $motorTentativas++
  }
  if ($pendentes.Count -gt 0) { Start-Sleep -Seconds 2 }
}
foreach ($nome in $pendentes) {
  Write-Host "[!]  $nome não respondeu em 3 min: veja a janela '$nome' para o erro." -ForegroundColor Yellow
  if ($nome -eq 'Motor' -and (Test-Path $motorSaida)) {
    Write-Host '     Últimas linhas do motor:' -ForegroundColor Yellow
    Get-Content $motorSaida -Tail 15 | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkYellow }
  }
  if ($nome -eq 'ZAP' -and (Test-Path $zapSaida)) {
    Write-Host '     Últimas linhas do ZAP:' -ForegroundColor Yellow
    Get-Content $zapSaida -Tail 15 | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkYellow }
  }
}

if (-not $SemNavegador -and (Test-Porta 4200)) {
  Start-Process 'http://localhost:4200'
}
Write-Host ''
Write-Host 'Pronto: http://localhost:4200  (para fechar tudo: parar.cmd)' -ForegroundColor Green
