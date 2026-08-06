@echo off
cd /d %~dp0

if not exist "node_modules" (
  echo Installing dependencies first...
  call npm install
)

node selftest.js --spawn
echo.
pause
