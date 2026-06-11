"""
Registry existence check for PyPI / npm.

Shared by the REST server (``server.py``, for the OpenAI GPT Action) and the
stdio MCP server (``mcp_server.py``, for Claude Code) so the anti-slopsquatting
logic lives in exactly one place. Uses ``requests`` (declared in
``requirements.txt``).
"""

from __future__ import annotations

import requests

PYPI_URL = "https://pypi.org/pypi/{pkg}/json"
NPM_URL = "https://registry.npmjs.org/{pkg}"

_SLOPSQUAT_WARNING = (
    "'{name}' was not found on {registry}. This is a slopsquatting risk — "
    "AI models invent plausible package names that attackers pre-register. "
    "Do not install it without confirming the correct name."
)


# Keep-alive connection pool + tiny in-process cache: repeated lookups in one
# session shouldn't pay a fresh TLS handshake or re-hit the registry.
_SESSION = requests.Session()
# Ask npm for abbreviated metadata — full packuments for popular packages are
# multiple MB; we only need existence + dist-tags.
_NPM_HEADERS = {"Accept": "application/vnd.npm.install-v1+json"}
_CACHE: dict[tuple[str, str], dict] = {}


def check_package(package: str, registry: str = "pypi") -> dict:
    """Verify a package exists on PyPI or npm.

    Returns ``{"exists": True|False|None, "latest_version": str|None,
    "warning": str|None}``. ``exists`` is tri-state: ``None`` means the
    registry could not be reached — callers MUST NOT treat that as "missing"
    (a network blip is not a slopsquatting verdict).
    """
    name = package.strip()
    key = (registry, name)
    if key in _CACHE:
        return dict(_CACHE[key])

    result: dict
    try:
        if registry == "pypi":
            resp = _SESSION.get(PYPI_URL.format(pkg=name), timeout=10)
        else:
            encoded = name.replace("/", "%2F")
            resp = _SESSION.get(NPM_URL.format(pkg=encoded), timeout=10,
                                headers=_NPM_HEADERS)
        if resp.status_code == 200:
            body = resp.json()
            version = (body.get("info", {}).get("version") if registry == "pypi"
                       else body.get("dist-tags", {}).get("latest"))
            result = {"exists": True, "latest_version": version, "warning": None}
        elif resp.status_code == 404:
            result = {
                "exists": False,
                "latest_version": None,
                "warning": _SLOPSQUAT_WARNING.format(name=name, registry=registry),
            }
        else:
            # 5xx / rate limit — unknown, don't cache a transient failure.
            return {
                "exists": None,
                "latest_version": None,
                "warning": f"{registry} returned HTTP {resp.status_code} — could not verify.",
            }
    except requests.RequestException as exc:
        return {
            "exists": None,
            "latest_version": None,
            "warning": f"Could not reach {registry}: {exc}",
        }

    _CACHE[key] = dict(result)
    return result
