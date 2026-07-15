@echo off
echo =======================================================
echo   FYP DDoS Detection System Dashboard
echo =======================================================

:: Add Wireshark to PATH for this session only so tshark can be found
set PATH=%PATH%;D:\Wireshark

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    pause
    goto :EOF
)

:: Wait 2 seconds, then open the default web browser to the dashboard
echo Starting browser...
start "" "http://localhost:5000"

:: Start the Flask app
echo Starting Flask Server...
python app.py

pause
