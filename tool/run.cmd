@echo off
chcp 65001>nul
cd /d "%~dp0"
echo === TikTok login launcher (account.txt x proxy.txt) ===
node batch.mjs %*
echo.
pause
