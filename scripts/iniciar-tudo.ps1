# Sobe o ambiente local do Checkop, cada serviço numa janela própria:
#   ZAP (8091) · motor Python (8010) · backend (8080) · front (4200) · laboratório (3000)
#
# Uso (na raiz do projeto):
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar-tudo.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar-tudo.ps1 -SemLab   (sem o alvo de teste)

param([switch]$SemLab)

$root    = Split-Path $PSScriptRoot -Parent
$backend = Join-Path $root 'backend'
$envFile = Join-Path $backend '.env'

if (-not (Test-Path $envFile)) { throw "Falta backend\.env. Copie backend\.env.example e preencha (veja o SETUP.md)." }

$keyLine = Select-String $envFile -Pattern '^\s*ZAP_API_KEY\s*=\s*(.*)$' | Select-Object -First 1
$key = if ($keyLine) { $keyLine.Matches[0].Groups[1].Value.Trim().Trim('"') } else { '' }
if (-not $key) { throw "ZAP_API_KEY está vazio no backend\.env." }

# aceita o ZAP do instalador (ZAP\Zed Attack Proxy) ou do zip (ZAP_2.17.0)
$zapBat = Get-ChildItem (Join-Path $backend 'tools\zap') -Recurse -Filter 'zap.bat' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $zapBat) { throw "ZAP não encontrado em backend\tools\zap. Rode scripts\baixar-ferramentas.ps1." }

function Abrir($titulo, $pasta, $comando) {
  $cmd = "`$Host.UI.RawUI.WindowTitle = '$titulo'; Set-Location -LiteralPath '$pasta'; $comando"
  Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmd
}

Abrir 'ZAP :8091'     $zapBat.DirectoryName                         ".\zap.bat -daemon -host 127.0.0.1 -port 8091 -config api.key=$key"
Abrir 'Motor :8010'   (Join-Path $backend 'src\py\security_engine') 'python -m uvicorn app.main:app --host 127.0.0.1 --port 8010'
Abrir 'Backend :8080' $backend                                      'npm start'
Abrir 'Front :4200'   (Join-Path $root 'front-end')                 'npx ng serve'
if (-not $SemLab) {
  Abrir 'Lab :3000'   (Join-Path $backend 'lab')                    'node lab-vulneravel.mjs'
}

Write-Host 'Abrindo as janelas. O ZAP leva uns 15-30 s; depois acesse http://localhost:4200'
