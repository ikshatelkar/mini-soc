"""Removes the notifier's autostart entry. Run: python notifier_autostart_uninstall.py

Does not stop a notifier that is already running right now - end that from
Task Manager if needed. This only stops it from starting again at your next
login.
"""

import os

from notifier_autostart_install import SHORTCUT_PATH

if __name__ == '__main__':
    if os.path.exists(SHORTCUT_PATH):
        os.remove(SHORTCUT_PATH)
        print(f'Removed: {SHORTCUT_PATH}')
    else:
        print('Nothing to remove - the notifier was not set to autostart.')
