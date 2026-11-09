@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -m PyInstaller --noconfirm --clean --onefile --windowed --name IPAUploader ^
  --icon "%~dp0ipa.ico" ^
  --add-data "%~dp0ipa.ico;." ^
  --version-file "%~dp0version_info.txt" ^
  --distpath "%~dp0dist" --workpath "%~dp0build" --specpath "%~dp0build" ^
  "%~dp0app.pyw"
if errorlevel 1 (
  echo.
  echo 打包失败，请检查上方日志。
) else (
  echo.
  echo 已生成 dist\IPAUploader.exe
)
pause
