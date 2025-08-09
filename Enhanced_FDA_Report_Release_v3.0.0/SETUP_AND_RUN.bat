@echo off
echo =====================================================
echo Enhanced FDA Report App v3.0.0 - Setup and Launch
echo =====================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    echo.
    pause
    exit /b 1
)

echo ✓ Python is installed
python --version

echo.
echo Installing required packages...
echo ================================

REM Install requirements
pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo ERROR: Failed to install requirements
    echo Please check your internet connection and try again
    pause
    exit /b 1
)

echo.
echo ✓ All requirements installed successfully
echo.
echo Starting Enhanced FDA Report App...
echo ===================================

REM Launch the application
python Enhanced_FDA_Report_app.py

echo.
echo Application closed.
pause
