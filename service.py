"""Windows Service wrapper for Mini SOC.

This is what makes "runs in the background" actually true. Wraps the Flask
dashboard and all monitoring threads as a real Windows Service using pywin32
(already a project dependency - nothing new to buy or install for this part).
Once installed, Windows starts it automatically on boot, before anyone logs
in, and restarts it if it ever crashes (once the recovery options in
service_install.bat are set) - no terminal window to remember to reopen.

Two things behave differently here than running `python app.py` by hand:

1. **No console.** A service has nowhere to print to, so before anything else
   starts, stdout/stderr are redirected into a rotating log file
   (logs/service.log). Every existing print() call in the codebase keeps
   working exactly as before - it just lands in a file instead of a window
   that no longer exists.
2. **No desktop.** Windows services run in "Session 0", which cannot show a
   UI - a deliberate, permanent anti-malware restriction, not a bug to work
   around. That's why notifier.py exists as a separate small program that runs
   in your own login session instead of in here - see its module docstring.

ONE-TIME SETUP (run once, from an Administrator PowerShell):
    python service.py install
    python service.py start

After that, this window never needs to be reopened - Windows manages the
service from here on. To make it survive a crash and restart automatically,
run service_install.bat once, which also sets that recovery policy (a plain
`install` alone does not).

Useful commands afterwards, still only needed if something goes wrong:
    python service.py stop
    python service.py remove
    python service.py debug     (runs in the foreground with output visible,
                                  for troubleshooting - not how it runs normally)
"""

import logging
import os
import sys
import threading
from logging.handlers import RotatingFileHandler

import servicemanager  # type: ignore
import win32event  # type: ignore
import win32service  # type: ignore
import win32serviceutil  # type: ignore

import config  # type: ignore


class _StreamToLogger:
    """Makes sys.stdout/sys.stderr write into the logging module instead of a
    console, so every existing print() call in the codebase keeps working
    unchanged under a service - it just lands in a file."""

    def __init__(self, logger: logging.Logger, level: int):
        self._logger = logger
        self._level = level

    def write(self, message: str) -> None:
        message = message.rstrip()
        if message:
            for line in message.splitlines():
                self._logger.log(self._level, line)

    def flush(self) -> None:
        pass


def _setup_service_logging() -> None:
    log_dir = os.path.join(config.BASE_DIR, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    handler = RotatingFileHandler(
        os.path.join(log_dir, 'service.log'), maxBytes=5_000_000, backupCount=3,
        encoding='utf-8',
    )
    handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logger = logging.getLogger('minisoc')
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    sys.stdout = _StreamToLogger(logger, logging.INFO)
    sys.stderr = _StreamToLogger(logger, logging.ERROR)


class MiniSOCService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'MiniSOC'
    _svc_display_name_ = 'Mini SOC Monitoring Service'
    _svc_description_ = (
        'Watches Windows event logs, files and network activity for security '
        'threats and serves the Mini SOC dashboard on 127.0.0.1.'
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._server = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # A service's working directory is not guaranteed to be this folder
        # (System32 is the usual default) - every path in this codebase is
        # already resolved relative to __file__ rather than cwd, so this isn't
        # strictly required, but it's a cheap safety net against anything that
        # assumes otherwise.
        os.chdir(config.BASE_DIR)
        _setup_service_logging()

        print('[*] Mini SOC service starting')
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ''),
        )

        try:
            from waitress.server import create_server  # type: ignore

            import app as app_module
            app_module.start_background_services()

            self._server = create_server(
                app_module.app, host=config.WEB_HOST, port=config.WEB_PORT,
            )
            threading.Thread(target=self._server.run, daemon=True, name='waitress').start()
            print(f'[*] Dashboard serving at http://{config.WEB_HOST}:{config.WEB_PORT}')
        except Exception:
            import traceback
            failure = traceback.format_exc()
            print('[!] Mini SOC service failed to start:')
            print(failure)
            servicemanager.LogErrorMsg(failure)
            # Returning now reports SERVICE_STOPPED to Windows. If recovery
            # actions are configured (service_install.bat), the SCM retries
            # on its own schedule rather than hot-looping immediately.
            return

        # Block here - this thread's only job until told to stop.
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        print('[*] Mini SOC service stopping')
        if self._server is not None:
            self._server.close()
        from core.pipeline import pipeline  # local import: only needed for shutdown
        pipeline.stop()
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ''),
        )


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(MiniSOCService)
