@echo off
setlocal
title PhishTracker - Windows Installer

echo =======================================================
echo        PhishTracker - Automated Windows Installer
echo =======================================================
echo.

:: 1. Check Python installation
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERROR: Python was not found on your system.
    echo [!] Please install Python 3.10+ from https://www.python.org/downloads/
    echo [!] Make sure to check the box "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [*] Python detected:
python --version
echo.

:: 2. Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

:: 3. Install requirements
echo [*] Installing required cybersecurity libraries...
echo [*] (rich, requests, dnspython, cryptography, PySocks, colorama, flask)
python -m pip install -r requirements.txt

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Warning: Some dependencies failed to install. Retrying with --user flag...
    python -m pip install -r requirements.txt --user
)

:: 4. Verify installation
echo.
echo [*] Verifying PhishTracker core engine...
python phish_tracker.py --fast -u "https://www.google.com" >nul 2>&1

if %ERRORLEVEL% EQU 0 (
    echo.
    echo =======================================================
    echo  [+] SUCCESS! PhishTracker is ready to use on Windows!
    echo =======================================================
    echo.
    echo  Quick Start Commands:
    echo    python phish_tracker.py                (Interactive Shell)
    echo    python phish_tracker.py -u "URL"       (Analyze single URL)
    echo    python phish_tracker.py -f samples\test_urls.txt (Batch mode)
    echo    python web_app.py                      (Launch Web UI)
    echo.
) else (
    echo.
    echo [!] Installation completed with warnings. Run 'python phish_tracker.py --help' to test.
    echo.
)

pause
