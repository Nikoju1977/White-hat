@echo off
setlocal
cd /d "%~dp0"
if not exist ".agent.env" (
 echo Jeton du collecteur absent. Enroler le terminal dans l'interface AEGIS.
 pause
 exit /b 1
)
py -m agent.collector --interval 60
pause
