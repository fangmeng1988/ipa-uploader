@echo off
chcp 65001 >nul
cd /d "%~dp0"
python "app.pyw"
echo.
echo Exit code: %errorlevel%
pause
