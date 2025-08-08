@echo off
echo Starting General Parasoft Report Viewer...
echo.

REM Activate virtual environment and run the application
call env\Scripts\activate.bat
python General_Parasoft_Report.py

echo.
echo Application finished.
pause
