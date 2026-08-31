@echo off
REM Mini SOC - one-time Windows Service installation.
REM
REM Right-click this file and choose "Run as administrator". This is the ONE
REM elevated step mentioned throughout the project - after this finishes,
REM Windows manages the service on its own and you never need an admin
REM window again for Mini SOC. It also starts on every future boot
REM automatically, before anyone logs in.

setlocal
cd /d "%~dp0"

echo Installing Mini SOC as a Windows Service...
python service.py install
if errorlevel 1 (
    echo.
    echo Install failed. The most common cause: this window is not running
    echo as Administrator. Right-click this file and choose
    echo "Run as administrator", then try again.
    pause
    exit /b 1
)

echo Setting startup type to Automatic - starts on boot, before anyone logs in...
sc config MiniSOC start= auto

echo Configuring automatic restart if the service ever crashes...
REM reset=86400: the failure counter forgets past crashes after a day of
REM stability, so one bad day doesn't count against it forever.
REM actions: restart after 1 minute, then 1 minute again, then back off to
REM 5 minutes if it keeps failing - avoids a tight crash-restart-crash loop.
sc failure MiniSOC reset= 86400 actions= restart/60000/restart/60000/restart/300000

echo Starting the service now...
python service.py start

echo.
echo Done. Mini SOC is running in the background and will start
echo automatically every time this computer boots.
echo.
echo Dashboard: http://127.0.0.1:5000
echo Log file:  logs\service.log
echo.
echo Next: run "python notifier_autostart_install.py" (no admin needed) so
echo you also get popups, not just the dashboard.
pause
