# Fecha o ambiente local do Checkop: encerra o que estiver escutando nas portas dos
# serviços (ZAP 8091, motor 8010, backend 8080, front 4200, laboratório 3000) e as
# janelas abertas pelo iniciar-tudo.ps1.
#
# Uso (na raiz do projeto): dois cliques em parar.cmd, ou
#   powershell -ExecutionPolicy Bypass -File scripts\parar-tudo.ps1

$servicos = [ordered]@{ 'ZAP' = 8091; 'Motor' = 8010; 'Backend' = 8080; 'Front' = 4200; 'Lab' = 3000 }

foreach ($nome in $servicos.Keys) {
  $porta = $servicos[$nome]
  $pids = Get-NetTCPConnection -LocalPort $porta -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique
  if (-not $pids) {
    Write-Host "[parado]     $nome (:$porta)" -ForegroundColor DarkGray
    continue
  }
  foreach ($id in $pids) {
    # /T encerra também os processos filhos (ex.: o java do ZAP aberto pelo zap.bat)
    & taskkill /PID $id /T /F | Out-Null
  }
  Write-Host "[encerrado]  $nome (:$porta)" -ForegroundColor Green
}

# ZAP que ainda estava subindo (ou travou) não escuta a porta, mas segura a pasta
# %USERPROFILE%\ZAP e impede o próximo de abrir: encerra pelo jar
Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -match 'zap-[\d.]+\.jar' } |
  ForEach-Object {
    & taskkill /PID $_.ProcessId /T /F | Out-Null
    Write-Host "[encerrado]  ZAP sem porta (pid $($_.ProcessId))" -ForegroundColor Green
  }

# janelas do PowerShell que o iniciar-tudo.ps1 abriu (pelo título)
$titulos = 'ZAP :8091', 'Motor :8010', 'Backend :8080', 'Front :4200', 'Lab :3000'
Get-Process powershell -ErrorAction SilentlyContinue |
  Where-Object { $titulos -contains $_.MainWindowTitle } |
  ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host 'Tudo encerrado.' -ForegroundColor Green
