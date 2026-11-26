@echo off
rem Fecha tudo o que o iniciar.cmd abriu (ZAP, motor, backend, front e laboratorio).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\parar-tudo.ps1"
pause
