@echo off
chcp 65001>nul
cd /d "%~dp0"
title TikTok login launcher (py)
echo === TikTok login launcher (py) : account.txt x proxy.txt ===

REM --- python co san deps (uu tien venv mobile, fallback python he thong) ---
set "PY=..\..\..\mobile\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

REM --- tu khoi dong signer offline neu :8799 chua chay ---
netstat -ano | findstr ":8799 " >nul 2>&1
if errorlevel 1 (
  echo [signer] chua chay -^> mo cua so signer :8799 ...
  start "Signer :8799" cmd /k "%~dp0signer.cmd"
  echo [signer] cho compile ~25s ...
  timeout /t 25 >nul
) else (
  echo [signer] :8799 da chay san.
)
set SIGNER_URL=http://127.0.0.1:8799

echo.
"%PY%" batch.py %*
echo.
pause
