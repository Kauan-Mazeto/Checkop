@echo off
rem Sobe o Checkop inteiro (ZAP, motor, backend, front e laboratorio), cada um numa janela.
rem Dois cliques aqui, ou no terminal: iniciar.cmd   (iniciar.cmd -SemLab para pular o laboratorio)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\iniciar-tudo.ps1" %*
pause
