@echo off
REM SelfishNet CLI launcher - auto-elevates to Administrator, then runs the tool.
REM
REM   Double-click            -> runs with no args (auto-loads devices.txt)
REM   run.bat --scan          -> scan the LAN
REM   run.bat --config x.txt  -> use a specific device list
REM
REM Any arguments you pass are forwarded to selfishnet.py.

setlocal

REM --- Elevate if we're not already Administrator ---------------------------
REM (branch on args: Start-Process rejects an empty -ArgumentList string)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    if "%~1"=="" (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

REM --- Run from the script's own folder ------------------------------------
cd /d "%~dp0"

REM --- Prefer the Python launcher 'py', fall back to 'python' ---------------
where py >nul 2>&1 && (set "PY=py") || (set "PY=python")

%PY% "%~dp0selfishnet.py" %*

echo.
pause
endlocal
