@echo off
cd /d "%~dp0"
echo ================================
echo  TEAvault Development Mode
echo ================================
echo.
echo Starting frontend dev server on http://localhost:5173 ...
echo Starting Tauri dev server...
echo.
start "Frontend" cmd /c "cd /d %%dp0ui && npm run dev"
timeout /t 10
cd src-tauri
tauri dev
pause