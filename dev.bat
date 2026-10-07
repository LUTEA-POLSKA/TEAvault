@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
echo ================================
echo  TEAvault Development Mode
echo ================================
echo.
echo Starting frontend dev server on http://localhost:5173 ...
echo Starting Tauri dev server...
echo.
start "" cmd /k "cd /d \"%~dp0ui\" && npm run dev"
timeout /t 10 >nul
cd /d "%~dp0src-tauri"
tauri dev
pause