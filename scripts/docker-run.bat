@echo off
REM GuardScan Docker Run Script for Windows
REM This script builds and runs the GuardScan container

echo Building GuardScan Docker image...
docker compose build

if %errorlevel% neq 0 (
    echo Failed to build Docker image.
    pause
    exit /b %errorlevel%
)

echo.
echo Starting GuardScan Web Container...
docker compose up -d guardscan-web

echo.
echo GuardScan is running! Open http://localhost:5000 in your browser.
pause
