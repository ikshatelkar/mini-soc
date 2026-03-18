import os

# Set to True to generate fake logs for testing. Set to False for real-world use.
USE_DUMMY_DATA = False

# The directory you want to monitor for file changes.
# Recommended Windows Paths:
#  - "C:\\Windows\\System32\\drivers\\etc" (Monitors your hosts file for DNS hijacks)
#  - "C:\\inetpub\\wwwroot" (Monitors an IIS web server for defacements)
# By default we are still pointing to test_dir, you should change this below!
FIM_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_dir')

# The log file you want to monitor for suspicious activity.
# Recommended Windows Paths:
#  - "C:\\ProgramData\\ssh\\logs\\sshd.log" (If you have OpenSSH installed)
#  - "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex230318.log" (IIS Log)
# By default we are pointing to the dummy log to prevent breaking if left unconfigured.
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'logs', 'dummy_auth.log')
