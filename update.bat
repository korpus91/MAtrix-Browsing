@echo off
cd /d %~dp0
echo Fetching the latest version...
echo.
git pull
echo.

if not exist "node_modules" goto install
echo Checking dependencies...
call npm install
goto done

:install
echo Installing dependencies...
call npm install

:done
echo.
echo ================================================
echo  Updated. Now double-click START.BAT to run it,
echo  or SELFTEST.BAT to check everything works.
echo ================================================
echo.
pause
