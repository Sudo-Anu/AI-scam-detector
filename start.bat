@echo off
setlocal EnableDelayedExpansion
title AI Scam Detector -- Launcher

:: ANSI colour helpers
for /f %%a in ('echo prompt $E^| cmd /q') do set "ESC=%%a"
set "GREEN=%ESC%[92m"
set "YELLOW=%ESC%[93m"
set "RED=%ESC%[91m"
set "CYAN=%ESC%[96m"
set "BOLD=%ESC%[1m"
set "RESET=%ESC%[0m"

:: Project paths  (strip trailing backslash from %~dp0)
set "ROOT=%~dp0"
if "!ROOT:~-1!"=="\" set "ROOT=!ROOT:~0,-1!"
set "BACKEND=!ROOT!\backend"
set "FRONTEND=!ROOT!\frontend"
set "VENV=!BACKEND!\venv"
set "REQUIREMENTS=!BACKEND!\requirements.txt"
set "ENV_FILE=!ROOT!\.env"

set "_BK=%TEMP%\scam_backend.bat"
set "_FE=%TEMP%\scam_frontend.bat"

echo.
echo !BOLD!!CYAN!AI Scam Detector Setup and Runner !RESET!
echo.

:: [1/6] Python
echo !YELLOW![1/6]!RESET! Checking Python...
where python >nul 2>&1
if errorlevel 1 (
    echo !RED![ERROR]!RESET! Python not found.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do set "PYVER=%%v"
echo !GREEN![OK]!RESET! !PYVER! detected.

:: [2/6] Node / npm
echo !YELLOW![2/6]!RESET! Checking Node.js / npm...
where npm >nul 2>&1
if errorlevel 1 (
    echo !RED![ERROR]!RESET! npm not found in PATH.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('npm --version 2^>^&1')  do set "NPMVER=%%v"
echo !GREEN![OK]!RESET! npm v!NPMVER! detected.

:: [3/6] Virtual environment
echo !YELLOW![3/6]!RESET! Checking Python virtual environment...
if not exist "!VENV!\Scripts\activate.bat" (
    echo !YELLOW![INFO]!RESET! venv missing -- creating at backend\venv...
    python -m venv "!VENV!"
    if errorlevel 1 (
        echo !RED![ERROR]!RESET! Failed to create venv.
        pause & exit /b 1
    )
)
call "!VENV!\Scripts\activate.bat"
echo !GREEN![OK]!RESET! venv activated.

:: [4/6] Python dependencies
echo !YELLOW![4/6]!RESET! Checking Python dependencies...
if not exist "!VENV!\.installed" (
    echo !YELLOW![INFO]!RESET! Installing dependencies... (This might take a while)
    python -m pip install --upgrade pip --quiet
    python -m pip install -r "!REQUIREMENTS!" --quiet
    if errorlevel 1 (
        echo !RED![ERROR]!RESET! pip install failed. Check network / requirements.txt.
        pause & exit /b 1
    )
    echo 1 > "!VENV!\.installed"
    echo !GREEN![OK]!RESET! Dependencies installed successfully.
) else (
    echo !GREEN![OK]!RESET! Dependencies already installed.
)

:: [5/6] npm dependencies
echo !YELLOW![5/6]!RESET! Checking frontend npm dependencies...
if not exist "!FRONTEND!\node_modules" (
    echo !YELLOW![INFO]!RESET! node_modules missing -- running npm install...
    pushd "!FRONTEND!"
    npm install --silent
    if errorlevel 1 (
        echo !RED![ERROR]!RESET! npm install failed.
        popd & pause & exit /b 1
    )
    popd
    echo !GREEN![OK]!RESET! npm packages installed.
) else (
    echo !GREEN![OK]!RESET! node_modules already present.
)

:: [6/6] API keys
echo !YELLOW![6/6]!RESET! Verifying API keys in .env...
if not exist "!ENV_FILE!" (
    echo # AI Scam Detector>"!ENV_FILE!"
)
call :CHECK_KEY "GEMINI_API_KEY"     "Gemini API Key"
call :CHECK_KEY "VIRUSTOTAL_API_KEY" "VirusTotal API Key"
call :CHECK_KEY "GOOGLE_API_KEY"     "Google API Key"
echo !GREEN![OK]!RESET! API keys checked.

:: Write helper scripts
(
    echo @echo off
    echo title ScamDetector-Backend
    echo cd /d "!ROOT!"
    echo call "!VENV!\Scripts\activate.bat"
    echo echo.
    echo echo  Backend: http://127.0.0.1:8000
    echo echo.
    echo python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
) > "!_BK!"

(
    echo @echo off
    echo title ScamDetector-Frontend
    echo cd /d "!FRONTEND!"
    echo echo.
    echo echo  Frontend: http://localhost:5173
    echo echo.
    echo npm run dev
) > "!_FE!"

:: Launch servers
echo.
echo !BOLD!!CYAN!Launching servers...!RESET!
echo.

start "ScamDetector-Backend"  /MIN cmd /k "%_BK%"
start "ScamDetector-Frontend" /MIN cmd /k "%_FE%"

:: Open browser immediately, wait briefly so servers can bind ports
timeout /t 2 /nobreak >nul
start "" "http://localhost:5173"

echo !BOLD!Both servers are running in minimised windows.!RESET!
echo Close "ScamDetector-Backend" and "ScamDetector-Frontend" to stop.
echo.
pause
exit /b 0

:: ============================================================
:: SUBROUTINE :CHECK_KEY
:: ============================================================
:CHECK_KEY
set "_KEY=%~1"
set "_LABEL=%~2"
set "_VALUE="
for /f "usebackq tokens=1,* delims==" %%A in ("!ENV_FILE!") do (
    if /i "%%A"=="!_KEY!" set "_VALUE=%%B"
)
if defined _VALUE set "_VALUE=!_VALUE: =!"
if not defined _VALUE (
    echo.
    echo !YELLOW!  [MISSING]!RESET! !_LABEL! ^(!_KEY!^) is not set.
    set /p "_NEW=  Enter !_LABEL!: "
    if "!_NEW!"=="" (
        echo !RED!  [WARN] Skipped -- some features may not work.!RESET!
        goto :EOF
    )
    echo !_KEY!=!_NEW!>>"!ENV_FILE!"
    echo !GREEN!  [SAVED]!RESET! !_KEY! appended to .env.
) else (
    echo !GREEN!  [OK]!RESET!  !_KEY! is set.
)
goto :EOF