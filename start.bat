@echo off
cd /d %~dp0

if not exist "node_modules" (
  echo First run -- installing dependencies, this takes a minute...
  call npm install
)

if not exist ".env" (
  echo.
  echo No .env file found. ORACLE chat needs a real API key to work.
  echo Copy .env.example to .env and paste your key in, then run this again.
  echo SPECS will still work right now without it.
  echo.
)

start "" cmd /c "timeout /t 2 >nul && start http://localhost:4173"
node server.js
pause
