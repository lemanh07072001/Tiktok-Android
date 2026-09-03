@echo off
chcp 65001>nul
cd /d "%~dp0"
title Login 1 account (py)
echo === Login 1 account (py) -^> hien info + luu session ===

set "PY=..\..\..\mobile\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

REM --- tu khoi dong signer offline neu :8799 chua chay ---
netstat -ano | findstr ":8799 " >nul 2>&1
if errorlevel 1 (
  echo [signer] chua chay -^> mo cua so signer :8799 ...
  start "Signer :8799" cmd /k "%~dp0signer.cmd"
  echo [signer] cho compile ~25s ...
  timeout /t 25 >nul
)
set SIGNER_URL=http://127.0.0.1:8799

echo.
echo Dang account: user^|pass^|email^|MailTM@   (giu ca @ o mailpass)
set /p ACC=account:
set /p PX=proxy ip:port:user:pass (Enter = bo qua):
if not "%PX%"=="" (
  for /f "tokens=1-4 delims=:" %%a in ("%PX%") do set "PROXY_URL=http://%%c:%%d@%%a:%%b"
)
echo.
"%PY%" worker.py "%ACC%"
