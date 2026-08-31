@echo off
REM Stops and removes the Mini SOC Windows Service. Run as administrator.
REM This does not touch your data (mini_soc.db, rules/, config_local.py) -
REM it only removes the background-service registration.

setlocal
cd /d "%~dp0"

echo Stopping Mini SOC service (if running)...
python service.py stop

echo Removing Mini SOC service...
python service.py remove
if errorlevel 1 (
    echo.
    echo Remove failed. Make sure this window is running as Administrator.
    pause
    exit /b 1
)

echo.
echo Done. The service is uninstalled. Your alert history and configuration
echo are untouched. Run service_install.bat again any time to reinstall.
pause
