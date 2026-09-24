@echo off
setlocal enabledelayedexpansion

title RTL-SDR Web Spectrum Scanner Launcher

echo.
echo ==================================================================
echo    RTL-SDR Web Spectrum Scanner Launcher
echo ==================================================================
echo.

:: 1. Check for Node.js
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Node.js is not installed or not in your system PATH.
    echo.
    where winget >nul 2>nul
    if %errorlevel% equ 0 (
        set /p INSTALL_CHOICE="Would you like to install Node.js automatically via winget? (Y/N): "
        if /i "!INSTALL_CHOICE!"=="Y" (
            echo Installing Node.js LTS via winget...
            winget install OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
            echo.
            echo Installation complete. Please close this window and run start_windows.bat again.
            pause
            exit /b 0
        )
    )
    
    echo Opening Node.js official download website in your default browser...
    start https://nodejs.org/
    echo Please download and run the Windows (.msi) installer, then re-launch this script.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node -v') do set NODE_VER=%%i
echo [OK] Node.js is ready: %NODE_VER%

:: 2. Check for Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    where py >nul 2>nul
    if %errorlevel% neq 0 (
        echo [!] Python 3 was not detected. The native RF bridge engine requires Python 3.
        echo Opening Python download page...
        start https://www.python.org/downloads/
        echo Please ensure you check "Add Python to PATH" during installation.
        pause
        exit /b 1
    )
)

echo [OK] Python is ready.
echo.

:: 3. Launch browser in background after 2 seconds
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:8080"

:: 4. Start the Node.js application server
echo Starting RTL-SDR Web Spectrum Application...
echo Access on this PC:  http://localhost:8080
echo Access on iPad/LAN: http://^<Your-PC-IP^>:8080
echo.
echo Press Ctrl+C in this window to stop the application.
echo ==================================================================
echo.

node server.js
pause
