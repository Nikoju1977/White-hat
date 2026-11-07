@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (
 echo Python n'est pas detecte. Installez Python 3.10 ou superieur.
 pause
 exit /b 1
)
if not exist ".env" (
 echo Premier lancement : generation des cles et du mot de passe.
 py -m pip install -r requirements.txt
 if errorlevel 1 exit /b 1
 py -m aegis.cli init
 if errorlevel 1 exit /b 1
)
echo Serveur AEGIS sur http://127.0.0.1:8765
py -m uvicorn aegis.main:app --host 127.0.0.1 --port 8765
pause
