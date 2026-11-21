"""Host classification for callback URLs.

DNS is not used. Resolving a name would leave the machine and could stall a check.
"""

import ipaddress
import re
from urllib.parse import urlsplit

_V4_FORBIDDEN = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_V6_FORBIDDEN = (
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
)

_NUMERIC_HOST = re.compile(r"[0-9.]+")
_HEXISH_HOST = re.compile(r"[0-9a-f:.]+", re.IGNORECASE)
_INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".corp", ".lan", ".home", ".intranet")
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "metadata.google.internal", "metadata.internal"}


def _parse_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if host.isdigit():
        value = int(host)
        if 0 <= value <= 0xFFFFFFFF:
            try:
                return ipaddress.ip_address(value)
            except ValueError:
                return None
    return None


def _unwrap(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _ambiguous_ip_literal(host: str) -> bool:
    if _parse_ip(host) is not None:
        return False
    if _NUMERIC_HOST.fullmatch(host):
        return True
    return ":" in host and _HEXISH_HOST.fullmatch(host) is not None


def host_is_forbidden(host: str, *, reject_ambiguous: bool = False) -> bool:
    """True when a hostname is loopback, private, link-local, or an internal name."""
    if not isinstance(host, str):
        return False
    normalized = host.strip().rstrip(".").lower()
    if not normalized:
        return False
    normalized = normalized.split("%", 1)[0]
    if normalized in _LOCAL_NAMES or normalized.endswith(_INTERNAL_SUFFIXES):
        return True
    ip = _parse_ip(normalized)
    if ip is None:
        return bool(reject_ambiguous and _ambiguous_ip_literal(normalized))
    ip = _unwrap(ip)
    nets = _V4_FORBIDDEN if isinstance(ip, ipaddress.IPv4Address) else _V6_FORBIDDEN
    return any(ip in net for net in nets)


def is_forbidden_callback(url: str) -> bool:
    """True when a callback URL must be rejected. The URL is never fetched."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        return True
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    if parts.scheme.lower() not in {"http", "https"}:
        return True
    host = parts.hostname
    if not host:
        return True
    return host_is_forbidden(host, reject_ambiguous=True)
