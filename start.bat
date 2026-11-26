@echo off
setlocal EnableDelayedExpansion
title Guardian AI -- Launcher

:: -- Project paths ---------------------------------------------
set "ROOT=%~dp0"
if "!ROOT:~-1!"=="\" set "ROOT=!ROOT:~0,-1!"
set "BACKEND=!ROOT!\backend"
set "FRONTEND=!ROOT!\frontend"
set "VENV=!BACKEND!\venv"
set "REQUIREMENTS=!BACKEND!\requirements.txt"
set "ENV_FILE=!ROOT!\.env"
set "_BK=%TEMP%\guardian_backend.bat"
set "_FE=%TEMP%\guardian_frontend.bat"

echo.
echo  ============================================
echo   *** Guardian AI -- Quick Launcher ***
echo  ============================================
echo.

:: -- [1/6] Python ----------------------------------------------
echo [1/6] Checking Python...
set "PYVER="
py -3 --version > "%TEMP%\pyver.tmp" 2>&1
if not errorlevel 1 (
    set /p PYVER=<"%TEMP%\pyver.tmp"
    del "%TEMP%\pyver.tmp" >nul 2>&1
    goto :PYTHON_OK
)
python --version > "%TEMP%\pyver.tmp" 2>&1
if errorlevel 1 (
    del "%TEMP%\pyver.tmp" >nul 2>&1
    echo [ERROR] Python not found. Install Python 3.10+ from https://python.org
    pause & exit /b 1
)
set /p PYVER=<"%TEMP%\pyver.tmp"
del "%TEMP%\pyver.tmp" >nul 2>&1
:PYTHON_OK
echo [OK] !PYVER! detected.

:: -- [2/6] Node.js / npm ---------------------------------------
echo [2/6] Checking Node.js / npm...
call npm --version > "%TEMP%\npmver.tmp" 2>&1
if errorlevel 1 (
    del "%TEMP%\npmver.tmp" >nul 2>&1
    echo [ERROR] npm not found. Install Node.js 18+ from https://nodejs.org
    pause & exit /b 1
)
set /p NPMVER=<"%TEMP%\npmver.tmp"
del "%TEMP%\npmver.tmp" >nul 2>&1
echo [OK] npm v!NPMVER! detected.

:: -- [3/6] Virtual environment ---------------------------------
echo [3/6] Checking Python virtual environment...
if not exist "!VENV!\Scripts\activate.bat" (
    echo [INFO] Creating venv at backend\venv ...
    python -m venv "!VENV!"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause & exit /b 1
    )
)
call "!VENV!\Scripts\activate.bat"
echo [OK] venv activated.

:: -- [4/6] Python dependencies ---------------------------------
echo [4/6] Checking Python dependencies...
if not exist "!VENV!\.installed" (
    echo [INFO] Installing packages - first run, may take a while...
    "!VENV!\Scripts\python.exe" -m pip install --upgrade pip --quiet --no-warn-script-location
    "!VENV!\Scripts\python.exe" -m pip install -r "!REQUIREMENTS!" --quiet --no-warn-script-location
    if errorlevel 1 (
        echo [ERROR] pip install failed. Check your network or requirements.txt.
        pause & exit /b 1
    )
    echo 1 > "!VENV!\.installed"
    echo [OK] Python packages installed.
) else (
    echo [OK] Python packages already installed.
)

:: -- [5/6] npm dependencies ------------------------------------
echo [5/6] Checking frontend npm packages...
if not exist "!FRONTEND!\node_modules" (
    echo [INFO] Running npm install...
    pushd "!FRONTEND!"
    call npm install
    if errorlevel 1 (
        echo [ERROR] npm install failed.
        popd & pause & exit /b 1
    )
    popd
    echo [OK] npm packages installed.
) else (
    echo [OK] node_modules already present.
)

:: -- [6/6] Load .env + check keys ------------------------------
echo [6/6] Loading .env environment variables...
if not exist "!ENV_FILE!" (
    echo # Guardian AI environment variables > "!ENV_FILE!"
)
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("!ENV_FILE!") do (
    set "_K=%%A"
    set "_V=%%B"
    if defined _K if defined _V (
        set "!_K!=!_V!"
    )
)
call :CHECK_KEY "GEMINI_API_KEY"     "Gemini API Key"
call :CHECK_KEY "VIRUSTOTAL_API_KEY" "VirusTotal API Key"
call :CHECK_KEY "GOOGLE_API_KEY"     "Google Safe Browsing Key"
echo [OK] Environment loaded.

:: -- Write backend launcher ------------------------------------
(
    echo @echo off
    echo title Guardian-AI Backend
    echo cd /d "!ROOT!"
    echo call "!VENV!\Scripts\activate.bat"
    echo set "GEMINI_API_KEY=!GEMINI_API_KEY!"
    echo set "VIRUSTOTAL_API_KEY=!VIRUSTOTAL_API_KEY!"
    echo set "GOOGLE_API_KEY=!GOOGLE_API_KEY!"
    echo echo.
    echo echo  Backend  : http://127.0.0.1:8000
    echo echo  API Docs : http://127.0.0.1:8000/docs
    echo echo.
    echo "!VENV!\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
) > "!_BK!"

:: -- Write frontend launcher -----------------------------------
(
    echo @echo off
    echo title Guardian-AI Frontend
    echo cd /d "!FRONTEND!"
    echo echo.
    echo echo  Frontend : http://localhost:5173
    echo echo.
    echo call npm run dev
) > "!_FE!"

:: -- Launch both servers ---------------------------------------
echo.
echo  Launching servers...
echo.
start "Guardian-AI Backend"  /MIN cmd /k "!_BK!"
start "Guardian-AI Frontend" /MIN cmd /k "!_FE!"

echo [INFO] Waiting 4s for servers to initialize...
ping 127.0.0.1 -n 5 >nul
start "" "http://localhost:5173"

echo.
echo  ==============================================================
echo   Guardian AI is running!
echo.
echo   Frontend  : http://localhost:5173
echo   Backend   : http://127.0.0.1:8000
echo   API Docs  : http://127.0.0.1:8000/docs
echo  ==============================================================
echo.
echo  Servers are running in background windows.
echo  Close those command windows to stop the servers.
echo.
pause
exit /b 0

:CHECK_KEY
if defined %~1 (
    echo [OK]  %~1 is configured.
    goto :EOF
)
echo.
echo [MISSING] %~2 [%~1] not found in .env
set /p "_NEW=  Enter %~2 - press Enter to skip: "
if "!_NEW!"=="" (
    echo [WARN] Skipped -- features using %~1 may not work.
    goto :EOF
)
echo %~1=!_NEW!>> "!ENV_FILE!"
set "%~1=!_NEW!"
echo [SAVED] %~1 saved to .env.
goto :EOF
