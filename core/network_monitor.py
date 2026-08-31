"""Network monitor.

Enumerates every listening socket and established connection on the host via
psutil, replacing the previous implementation that probed four hardcoded ports on
localhost. That old approach could only ever find a backdoor if the attacker
happened to pick one of those four ports, and was blind to outbound connections
entirely - which is how most modern implants actually work, since dialling out
beats listening for inbound traffic through a NAT or firewall.

What this catches now:
  * a listener on any known-suspicious port, not just four
  * an *outbound* connection to a known-suspicious remote port (C2 beaconing)
  * a listening socket bound to all interfaces rather than loopback, which is the
    difference between a local dev server and something reachable from the network
  * the owning process for each finding, so an alert names a culprit
"""

from __future__ import annotations

import os
import time

import config  # type: ignore
from core.detect import process_network  # type: ignore
from core.pipeline import pipeline  # type: ignore

MODULE = 'NETWORK'

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
    PSUTIL_ERROR = None
except ImportError as exc:
    psutil = None  # type: ignore
    PSUTIL_AVAILABLE = False
    PSUTIL_ERROR = str(exc)

# Ports strongly associated with bind shells, RATs and C2 frameworks.
SUSPICIOUS_PORTS = {
    1337: 'Common bind shell port',
    4444: 'Metasploit default listener',
    4445: 'Metasploit alternate listener',
    5555: 'Android Debug Bridge / common RAT',
    6667: 'IRC (legacy botnet C2)',
    6697: 'IRC over TLS (legacy botnet C2)',
    8080: 'HTTP proxy / common C2 fallback',
    9001: 'Tor / common C2',
    9050: 'Tor SOCKS proxy',
    31337: 'Back Orifice',
}

# Ports that are suspicious to *connect out* to but unremarkable to listen on.
SUSPICIOUS_REMOTE_PORTS = {
    4444: 'Metasploit handler',
    1337: 'Bind shell',
    6667: 'IRC C2',
    9050: 'Tor SOCKS proxy',
    31337: 'Back Orifice',
}

WILDCARD_ADDRESSES = {'0.0.0.0', '::', '*'}

_reported: set[str] = set()
_status = {'status': 'not_started', 'detail': None, 'listeners': 0, 'connections': 0}


def _process_name(pid: int | None) -> str:
    if not pid:
        return 'unknown'
    try:
        return psutil.Process(pid).name()
    except Exception:
        # The process may have exited between enumeration and lookup, which is
        # normal for short-lived connections.
        return f'pid {pid}'


def scan_connections() -> None:
    """One pass over the host's sockets, alerting on state changes only."""
    if not PSUTIL_AVAILABLE:
        return

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        _status.update(status='degraded',
                       detail='Some sockets require elevation to attribute to a process.')
        connections = []
    except Exception as exc:
        _status.update(status='error', detail=str(exc))
        return

    current: set[str] = set()
    listeners = 0
    established = 0

    for conn in connections:
        if conn.status == psutil.CONN_LISTEN:
            listeners += 1
            port = conn.laddr.port
            if port in SUSPICIOUS_PORTS:
                key = f'listen:{port}:{conn.pid}'
                current.add(key)
                if key not in _reported:
                    process_network(
                        'listener',
                        {'port': port, 'pid': conn.pid,
                         'process': _process_name(conn.pid),
                         'bind_address': conn.laddr.ip},
                        port_description=SUSPICIOUS_PORTS[port],
                        network_exposed=conn.laddr.ip in WILDCARD_ADDRESSES,
                    )

        elif conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            established += 1
            rport = conn.raddr.port
            if rport in SUSPICIOUS_REMOTE_PORTS:
                key = f'egress:{conn.raddr.ip}:{rport}'
                current.add(key)
                if key not in _reported:
                    process_network(
                        'egress',
                        {'remote_ip': conn.raddr.ip, 'remote_port': rport,
                         'pid': conn.pid, 'process': _process_name(conn.pid)},
                        port_description=SUSPICIOUS_REMOTE_PORTS[rport],
                        source_ip=conn.raddr.ip,
                    )

    for key in _reported - current:
        kind, _, rest = key.partition(':')
        process_network(
            'closed',
            {'descriptor': rest,
             'kind_label': 'listener' if kind == 'listen' else 'connection'},
        )

    _reported.clear()
    _reported.update(current)
    _status.update(status='running', listeners=listeners, connections=established)
    if _status['detail'] is None:
        _status['detail'] = None


def monitor_status() -> dict:
    if not PSUTIL_AVAILABLE:
        return {'status': 'unavailable',
                'detail': f'psutil is not installed: {PSUTIL_ERROR}',
                'listeners': 0, 'connections': 0}
    return dict(_status)


def start_network_monitor(interval: int | None = None) -> None:
    interval = interval or config.NETWORK_SCAN_INTERVAL

    if not PSUTIL_AVAILABLE:
        print(f'[!] Network monitor disabled: psutil is not installed ({PSUTIL_ERROR})')
        _status.update(status='unavailable', detail=f'psutil missing: {PSUTIL_ERROR}')
        return

    print('[*] Starting Network Monitor (enumerating listeners and connections)')
    while True:
        pipeline.heartbeat(MODULE)
        try:
            scan_connections()
        except Exception as exc:
            print(f'[!] Network scan failed: {exc}')
        time.sleep(interval)
