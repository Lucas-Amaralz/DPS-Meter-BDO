@echo off
chcp 65001 >nul
set PYTHONUTF8=1
cd /d "%~dp0"
rem Analisa a captura mais recente e salva relatorio.txt dentro da pasta dela
for /f "delims=" %%d in ('dir /b /ad /o-n capturas') do (
  ".venv\Scripts\python.exe" analyze.py "capturas\%%d" > "capturas\%%d\relatorio.txt"
  type "capturas\%%d\relatorio.txt"
  goto fim
)
:fim
pause
