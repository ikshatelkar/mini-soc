"""Local secrets template - email credentials live here, never in config.py.

HOW TO USE THIS FILE
---------------------
1. Copy this file to `config_local.py` (same folder). config.py automatically
   loads config_local.py if it exists, and .gitignore already excludes
   config_local.py from version control - so your password never ends up
   committed to git or shared anywhere.
2. Fill in the values below.
3. Never paste your email password anywhere else (chat, issue trackers,
   screenshots) - the whole point of this file is to keep it in exactly one
   place, on your machine, that nothing else touches.

GETTING AN "APP PASSWORD" (you need this, not your normal email password)
---------------------------------------------------------------------------
Modern email providers block ordinary programs from logging in with your
regular password - you need to create a separate "app password" instead,
which can be revoked independently if this machine is ever compromised.

Gmail:
  1. Turn on 2-Step Verification if it isn't already: myaccount.google.com/security
  2. Go to myaccount.google.com/apppasswords
  3. Create a new app password (name it "Mini SOC"), copy the 16-character code
  4. Use EMAIL_SMTP_HOST = 'smtp.gmail.com', EMAIL_SMTP_PORT = 465

Outlook / Hotmail / Microsoft 365:
  1. account.microsoft.com/security -> Advanced security options
  2. Create an "app password" the same way
  3. Use EMAIL_SMTP_HOST = 'smtp.office365.com', EMAIL_SMTP_PORT = 587

Both are free - normal personal email accounts include SMTP sending at no
extra cost, with sending limits far beyond what this tool will ever produce.
"""

EMAIL_ENABLED = False  # flip to True once the settings below are filled in

# The account Mini SOC sends FROM.
EMAIL_SMTP_HOST = 'smtp.gmail.com'
EMAIL_SMTP_PORT = 465
EMAIL_USERNAME = 'your-account@gmail.com'
EMAIL_APP_PASSWORD = 'paste-your-16-character-app-password-here'

# Where alerts get sent TO. Usually the same address as above, but doesn't
# have to be - point it at a different inbox if you prefer.
EMAIL_TO = 'your-account@gmail.com'

# ---------------------------------------------------------------------------
# Dashboard login
# ---------------------------------------------------------------------------
#
# Nothing to fill in here. The first time the dashboard runs, core/auth.py
# generates a SECRET_KEY (used to sign your login session cookie) and appends
# it to config_local.py automatically, so it survives restarts without any
# manual step. If you ever see a SECRET_KEY = '...' line below this comment
# after copying this file, that's normal - it means the dashboard has already
# run once.

# ---------------------------------------------------------------------------
# Multi-machine setup (only if you're monitoring more than one computer)
# ---------------------------------------------------------------------------
#
# Skip this whole section for a single-machine install - the default
# DEPLOYMENT_ROLE = 'standalone' in config.py already does the right thing.
#
# ON THE SERVER (the one machine that stores alerts and shows the dashboard):
#   DEPLOYMENT_ROLE = 'server'
#   WEB_HOST = '0.0.0.0'   # so workers on the LAN can reach it, not just this PC
#
# ON EACH WORKER (every machine you want watched), run agent.py instead of
# app.py, and set the three values below. Get the token by signing into the
# server's dashboard -> "Enrolled Workers" -> enroll this worker; the token is
# displayed exactly once, right after you create it.
#   SERVER_URL = 'http://192.168.1.10:5000'   # your server's LAN address
#   AGENT_TOKEN = 'paste-the-token-shown-once-in-the-dashboard'
#   AGENT_NAME = 'FRONT-DESK-PC'              # how this worker appears there
#
# SECURITY NOTE: this traffic is plain HTTP for now, so it is only safe on a
# network you trust (a normal office LAN). Do not point a worker at a server
# across the open internet until HTTPS support exists.
