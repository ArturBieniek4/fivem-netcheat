import ipaddress
import socket
from urllib.parse import quote, urlparse

import requests


JOIN_URL = "https://cfx.re/join/{code}"
PRIVATE_PLACEHOLDER = "private-placeholder.cfx.re"


class CfxResolveError(RuntimeError):
    """Raised when a cfx.re join code cannot be resolved to an endpoint."""


def _endpoint_from_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise CfxResolveError("cfx.re returned an invalid server URL")
    if parsed.hostname.lower() == PRIVATE_PLACEHOLDER:
        raise CfxResolveError("this server hides its endpoint")

    try:
        port = parsed.port or 30120
    except ValueError as exc:
        raise CfxResolveError("cfx.re returned an invalid server port") from exc

    try:
        ipaddress.ip_address(parsed.hostname)
        host = parsed.hostname
    except ValueError:
        try:
            addresses = socket.getaddrinfo(
                parsed.hostname, port, family=socket.AF_INET, type=socket.SOCK_DGRAM
            )
        except socket.gaierror as exc:
            raise CfxResolveError(
                f"could not resolve server host {parsed.hostname!r}"
            ) from exc
        if not addresses:
            raise CfxResolveError(f"server host {parsed.hostname!r} has no IPv4 address")
        host = addresses[0][4][0]

    return f"{host}:{port}"


def get_ip(cfx_id: str) -> str:
    code = (cfx_id or "").strip().strip("/")
    if not code or "/" in code:
        raise CfxResolveError("invalid cfx.re join code")

    try:
        response = requests.get(
            JOIN_URL.format(code=quote(code, safe="")),
            allow_redirects=False,
            timeout=10,
            headers={"User-Agent": "FiveM-NetCheat/CFXResolver"},
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise CfxResolveError(f"cfx.re request failed: {exc}") from exc

    server_url = response.headers.get("X-CitizenFX-Url")
    if not server_url:
        raise CfxResolveError("cfx.re did not return a server endpoint")
    return _endpoint_from_url(server_url)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("usage: get_ip_from_cfx.py <join-code>")
    print(get_ip(sys.argv[1]))
