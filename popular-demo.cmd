@echo off
rem Popula o Checkop com dados de demonstração (contas, varreduras no laboratório e análise de código).
rem Rode DEPOIS do iniciar.cmd, com tudo no ar. Leva de 15 a 30 minutos.
rem Só análise de código (rápido):  popular-demo.cmd --so-codigo
chcp 65001 >nul
node "%~dp0scripts\popular-demo.mjs" %*
pause
