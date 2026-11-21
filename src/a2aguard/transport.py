"""Bounded HTTP for hygiene checks. No redirects, no unbounded reads."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from urllib.parse import urlparse


class TransportError(Exception):
    """The target could not be reached, or the response could not be read."""


class RemoteRefused(Exception):
    """A non-loopback target was refused because --allow-remote was not set."""


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> object:
        return json.loads(self.text)


def is_loopback_url(url: str) -> bool:
    host = urlparse(url).hostname
    if host is None:
        return False
    host = host.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_local(url: str, *, allow_remote: bool) -> None:
    if is_loopback_url(url):
        return
    if allow_remote:
        return
    raise RemoteRefused(url)


def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | dict | list | str | None = None,
    timeout: float = 2.0,
    retries: int = 1,
    max_response: int = 1_048_576,
) -> Response:
    """Send one HTTP request. `retries` is the number of extra attempts on transport failure."""
    last: Exception | None = None
    attempts = max(0, retries) + 1
    for _ in range(attempts):
        try:
            return _once(method, url, headers=headers, body=body, timeout=timeout, max_response=max_response)
        except TransportError as exc:
            last = exc
    assert last is not None
    raise last


def _encode_body(body: bytes | dict | list | str | None) -> tuple[bytes | None, str | None]:
    if body is None:
        return None, None
    if isinstance(body, bytes):
        return body, None
    if isinstance(body, str):
        return body.encode("utf-8"), "text/plain; charset=utf-8"
    return json.dumps(body).encode("utf-8"), "application/json"


def _once(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None,
    body: bytes | dict | list | str | None,
    timeout: float,
    max_response: int,
) -> Response:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TransportError(f"unsupported url: {url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    payload, content_type = _encode_body(body)
    hdrs = {k: v for k, v in (headers or {}).items()}
    if payload is not None:
        if not any(k.lower() == "content-type" for k in hdrs) and content_type:
            hdrs["Content-Type"] = content_type
        if not any(k.lower() == "content-length" for k in hdrs):
            hdrs["Content-Length"] = str(len(payload))
    conn_cls = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
    conn = conn_cls(parsed.hostname, port, timeout=timeout)
    try:
        conn.request(method.upper(), path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read(max_response + 1)
        if len(raw) > max_response:
            raw = raw[:max_response]
        header_map = {key.lower(): value for key, value in resp.getheaders()}
        return Response(status=resp.status, headers=header_map, body=raw)
    except (OSError, HTTPException, TimeoutError) as exc:
        raise TransportError(str(exc)) from exc
    finally:
        conn.close()
