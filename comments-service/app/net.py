"""HTTP saliente, aislado para que los tests puedan reemplazarlo."""

import httpx


def http_get(url: str, follow_redirects: bool = False) -> httpx.Response:
    return httpx.get(url, timeout=3, follow_redirects=follow_redirects)
