@echo off
chcp 65001>nul
cd /d "%~dp0"
title Signer offline :8799 (GIU MO)
echo ================================================================
echo   SIGNER offline (unidbg :8799) - GIU CUA SO NAY MO khi login
echo   (lan dau se compile unidbg ~20-40s, cho den khi thay "gateway")
echo ================================================================
set PORT=8799
node "..\..\..\mobile\server\server.mjs"
echo.
echo [signer da dung]
pause
