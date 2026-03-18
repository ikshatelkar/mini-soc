import urllib.request
import json
import ipaddress

# In-memory cache so same IP is only looked up once per session
_geo_cache = {}

# Private/reserved IP ranges - these cannot be geolocated
PRIVATE_PREFIXES = ('10.', '192.168.', '127.', '172.16.', '172.17.',
                    '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
                    '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                    '172.28.', '172.29.', '172.30.', '172.31.', '169.254.', '::1')


def _is_private(ip: str) -> bool:
    """Return True if the IP is a private/loopback/reserved address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def geolocate_ip(ip: str) -> dict | None:
    """
    Look up the geolocation of a public IP address using the free ip-api.com service.
    Returns a dict with keys: country, city, isp, lat, lon, query
    Returns None for private/invalid IPs or if the lookup fails.
    Caches results in memory.
    """
    if not ip or _is_private(ip):
        return None

    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,lat,lon,query"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())

        if data.get('status') == 'success':
            result = {
                'country': data.get('country', 'Unknown'),
                'city':    data.get('city', 'Unknown'),
                'isp':     data.get('isp', 'Unknown'),
                'lat':     data.get('lat'),
                'lon':     data.get('lon'),
                'query':   data.get('query', ip),
            }
            _geo_cache[ip] = result
            return result
    except Exception as e:
        print(f"[!] Geo lookup failed for {ip}: {e}")

    return None
