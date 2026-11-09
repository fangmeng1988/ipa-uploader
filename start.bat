@echo off
setlocal
cd /d "%~dp0"

set "PYW="
if exist "%LOCALAPPDATA%\Python\bin\pythonw.exe" set "PYW=%LOCALAPPDATA%\Python\bin\pythonw.exe"
if not defined PYW if exist "%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe"
if not defined PYW if exist "%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe"
if not defined PYW if exist "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"
if not defined PYW for /f "delims=" %%I in ('where pythonw 2^>nul') do if not defined PYW set "PYW=%%I"

if not defined PYW (
  echo pythonw.exe not found. Please install Python 3.10+ and try again.
  pause
  exit /b 1
)

start "" "%PYW%" "%~dp0app.pyw"
endlocal
