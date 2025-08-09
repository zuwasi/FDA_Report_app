@echo off
echo Installing requirements for Enhanced FDA Report App...
echo.

pip install -r requirements.txt

if %errorlevel% equ 0 (
    echo.
    echo All requirements installed successfully!
    echo You can now run the application or build it to an executable.
    echo.
) else (
    echo.
    echo Error installing requirements. Please check your Python installation.
    echo.
)

pause
