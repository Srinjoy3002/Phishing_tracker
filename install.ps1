# PhishTracker Automated PowerShell Installer for Windows
# Run with: .\install.ps1

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "       PhishTracker - Windows PowerShell Setup" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
try {
    $pyVer = python --version 2>&1
    Write-Host "[*] Python detected: $pyVer" -ForegroundColor Green
} catch {
    Write-Host "[!] ERROR: Python was not found in your PATH." -ForegroundColor Red
    Write-Host "[!] Please install Python from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "[!] Ensure 'Add Python to PATH' is checked during installation." -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Installing required dependencies..." -ForegroundColor Cyan
python -m pip install -r requirements.txt --quiet

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Green
    Write-Host " [+] SUCCESS! PhishTracker installed successfully!" -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host " Run the tool:" -ForegroundColor White
    Write-Host "   python phish_tracker.py" -ForegroundColor Cyan
    Write-Host "   python phish_tracker.py -u 'https://example.com'" -ForegroundColor Cyan
} else {
    Write-Host "[!] Retrying installation with --user flag..." -ForegroundColor Yellow
    python -m pip install -r requirements.txt --user
}
