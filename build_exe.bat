@echo off
echo Building Enhanced FDA Report App to executable...
echo.

REM Check if PyInstaller is installed
python -c "import PyInstaller" 2>NUL
if %errorlevel% neq 0 (
    echo PyInstaller not found. Installing...
    pip install pyinstaller
)

REM Create the executable
echo Creating executable...
pyinstaller --onefile --windowed --name "Enhanced_FDA_Report_app" "Enhanced_FDA_Report_app.py"

REM Check if build was successful
if exist "dist\Enhanced_FDA_Report_app.exe" (
    echo.
    echo BUILD SUCCESSFUL!
    echo Executable created at: dist\Enhanced_FDA_Report_app.exe
    echo.
    pause
) else (
    echo.
    echo BUILD FAILED!
    echo Check the output above for errors.
    echo.
    pause
)
