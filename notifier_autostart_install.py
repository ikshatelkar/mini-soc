"""One-time setup: start notifier.py automatically whenever you log into
Windows, so you get popups without having to remember to launch anything.

No administrator rights needed - unlike the service, this only touches your
own user account, via the Startup folder every Windows user already has
(the same mechanism countless ordinary programs use to start themselves
quietly at login).

Run once:
    python notifier_autostart_install.py

Undo:
    python notifier_autostart_uninstall.py
"""

import os
import sys

import win32com.client  # type: ignore

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
STARTUP_DIR = os.path.join(
    os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
SHORTCUT_PATH = os.path.join(STARTUP_DIR, 'Mini SOC Notifier.lnk')


def pythonw_path() -> str:
    """The windowless Python interpreter that ships next to the normal one -
    running the notifier through this instead of python.exe is what keeps a
    console window from popping up every time you log in."""
    candidate = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
    return candidate if os.path.exists(candidate) else sys.executable


def install() -> None:
    os.makedirs(STARTUP_DIR, exist_ok=True)
    shell = win32com.client.Dispatch('WScript.Shell')
    shortcut = shell.CreateShortCut(SHORTCUT_PATH)
    shortcut.TargetPath = pythonw_path()
    shortcut.Arguments = f'"{os.path.join(PROJECT_DIR, "notifier.py")}"'
    shortcut.WorkingDirectory = PROJECT_DIR
    shortcut.Description = 'Mini SOC alert notifier - shows popups for new alerts'
    shortcut.save()

    print(f'Installed: {SHORTCUT_PATH}')
    print('The notifier will start automatically next time you log in.')
    print()
    print('To start it right now, without logging out first, run:')
    print(f'  "{pythonw_path()}" "{os.path.join(PROJECT_DIR, "notifier.py")}"')


if __name__ == '__main__':
    install()
