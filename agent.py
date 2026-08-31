"""Phase 5 agent entry point - runs on a worker, not the server.

Starts only the collectors (core/fim.py, core/log_parser.py,
core/network_monitor.py, core/winevt.py) and the forwarder
(core/forwarder.py). Deliberately does NOT start a Flask app, does NOT call
init_db(), does NOT start the alert pipeline, and does NOT load rules - an
agent collects and forwards raw events; it never stores, correlates, or
decides anything locally. See core/detect.py's _route_event() and
core/forwarder.py's module docstring for why.

ONE-TIME SETUP on the worker machine, before running this:
    1. Enroll the worker from the server's dashboard (Enrolled Workers panel,
       or POST /api/agents while logged in) - this returns a token shown
       exactly once.
    2. Copy config_local.example.py to config_local.py on THIS machine and
       fill in SERVER_URL, AGENT_TOKEN (the token from step 1) and
       AGENT_NAME.

Running this sets DEPLOYMENT_ROLE to 'agent' for the process regardless of
what config_local.py says - there is no ambiguity about role when this is the
file you ran, and a stale/wrong DEPLOYMENT_ROLE would otherwise fail silently
(events would be evaluated against an empty local rule engine instead of
forwarded, since an agent install carries no rules). That assignment happens
inside main(), not at import: importing this module must not reconfigure the
process, the same way importing app.py starts nothing on its own.

SERVER_URL is plain http:// by design for this pass - see core/forwarder.py's
docstring. Treat it as LAN-only: never point an agent at a server across the
open internet until a future TLS pass exists.
"""

import sys
import threading

import config  # type: ignore
from core.detect import process_winevt  # type: ignore
from core.fim import start_fim_monitor  # type: ignore
from core.forwarder import forwarder  # type: ignore
from core.log_parser import start_log_monitor  # type: ignore
from core.network_monitor import start_network_monitor  # type: ignore
from core.winevt import start_event_log_collectors  # type: ignore


def _require_agent_config() -> None:
    missing = [name for name in ('SERVER_URL', 'AGENT_TOKEN', 'AGENT_NAME')
              if not getattr(config, name, None)]
    if missing:
        print('[!] agent.py cannot start: missing ' + ', '.join(missing) + '.')
        print('    Set these in this machine\'s own config_local.py - see '
              'config_local.example.py for the template, and the "ONE-TIME '
              'SETUP" note at the top of this file for how to get a token.')
        sys.exit(1)


def main() -> None:
    config.DEPLOYMENT_ROLE = 'agent'
    _require_agent_config()
    print(f'[*] Mini SOC agent "{config.AGENT_NAME}" starting, forwarding to '
          f'{config.SERVER_URL}')

    forwarder.start()

    threading.Thread(target=start_fim_monitor, daemon=True, name='fim').start()
    threading.Thread(target=start_log_monitor, daemon=True, name='log-monitor').start()
    threading.Thread(target=start_network_monitor, daemon=True,
                     name='network-monitor').start()
    if config.WINEVT_ENABLED:
        start_event_log_collectors(process_winevt)

    print('[*] Collectors running. Ctrl+C to stop.')
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print('\n[*] Mini SOC agent stopping')
        forwarder.stop()


if __name__ == '__main__':
    main()
