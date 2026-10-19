@echo off
chcp 65001 >nul
set PYTHONUTF8=1
cd /d "%~dp0"
".venv\Scripts\python.exe" meter.py %*
if %errorlevel%==3 goto denovo
pause
exit /b
rem Codigo 3 = o meter pediu para reiniciar (atualizacao)
:denovo
".venv\Scripts\python.exe" meter.py %*
if %errorlevel%==3 goto denovo
pause
