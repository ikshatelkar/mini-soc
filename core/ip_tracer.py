"""IP geolocation lookups against ip-api.com.

Never call this from a detection path. Lookups are network-bound and deliberately
rate limited, so a caller can block for seconds; the enrichment worker exists so
that waiting happens off to the side.

Note on the provider: ip-api.com's free tier is plain HTTP only (TLS requires a
paid key) and allows 45 requests/minute, banning sustained abuse. We ask for the
minimum fields we need and stay under the budget on purpose - a brute-force wave
from a botnet is exactly when enrichment must not get us blocked.
"""

import ipaddress
import json
import threading
import time
import urllib.request

API_URL = 'http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,lat,lon,query'


class RateLimiter:
    """Spaces calls evenly to stay under a per-minute budget.

    Even spacing rather than a burst-then-stall bucket, because the provider
    measures per minute and a burst is what trips abuse detection.
    """

    def __init__(self, per_minute: int):
        self._interval = 60.0 / max(1, per_minute)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self._interval
        if wait > 0:
            time.sleep(wait)


def is_geolocatable(ip: str) -> bool:
    """True only for public unicast addresses.

    `is_global` rather than `not is_private`, so loopback, link-local, multicast,
    broadcast and reserved ranges are all excluded - none of them can be
    geolocated and asking wastes rate-limit budget.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def geolocate_ip(ip: str, timeout: float = 5.0,
                 limiter: RateLimiter | None = None) -> tuple[dict | None, str]:
    """Resolve an IP to a location.

    Returns (geo, status) where status is one of:
      'success' - geo is populated
      'private' - not a routable public address, no lookup attempted
      'failed'  - the provider rejected it or the call errored
    """
    if not ip or not is_geolocatable(ip):
        return None, 'private'

    if limiter is not None:
        limiter.acquire()

    try:
        with urllib.request.urlopen(API_URL.format(ip=ip), timeout=timeout) as response:
            data = json.loads(response.read().decode())
    except Exception as exc:
        print(f'[!] Geo lookup failed for {ip}: {exc}')
        return None, 'failed'

    if data.get('status') != 'success':
        return None, 'failed'

    return {
        'country': data.get('country') or 'Unknown',
        'city':    data.get('city') or 'Unknown',
        'isp':     data.get('isp') or 'Unknown',
        'lat':     data.get('lat'),
        'lon':     data.get('lon'),
    }, 'success'
