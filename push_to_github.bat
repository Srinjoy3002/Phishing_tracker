@echo off
setlocal
title PhishTracker - Push to GitHub

echo =======================================================
echo     PhishTracker: GitHub Publishing Assistant
echo =======================================================
echo.
echo Step 1: Ensure you have created the empty repository on GitHub:
echo         https://github.com/new
echo         Repository Name: Phishing_tracker
echo         (Leave "Add README" UNCHECKED)
echo.
echo Step 2: Attempting to push to https://github.com/Srinjoy3002/Phishing_tracker.git
echo.

git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo =======================================================
    echo  SUCCESS! Your project is live at:
    echo  https://github.com/Srinjoy3002/Phishing_tracker
    echo =======================================================
) else (
    echo.
    echo -------------------------------------------------------
    echo  If push failed due to authentication:
    echo  1. Create a Personal Access Token (classic):
    echo     https://github.com/settings/tokens
    echo     Check the [repo] scope, copy the token.
    echo.
    echo  2. Run the following command with your token:
    echo     git remote set-url origin https://<YOUR_TOKEN>@github.com/Srinjoy3002/Phishing_tracker.git
    echo     git push -u origin main
    echo -------------------------------------------------------
)

pause
