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


def check_package(package: str, registry: str = "pypi") -> dict:
    """Verify a package exists on PyPI or npm.

    Returns a dict: ``{"exists": bool, "latest_version": str|None, "warning": str|None}``.
    Network errors are returned as a warning rather than raised, so callers
    (REST and MCP) get a uniform, JSON-serialisable result.
    """
    name = package.strip()
    try:
        if registry == "pypi":
            resp = requests.get(PYPI_URL.format(pkg=name), timeout=10)
            if resp.status_code == 200:
                version = resp.json().get("info", {}).get("version")
                return {"exists": True, "latest_version": version, "warning": None}
        else:
            encoded = name.replace("/", "%2F")
            resp = requests.get(NPM_URL.format(pkg=encoded), timeout=10)
            if resp.status_code == 200:
                version = resp.json().get("dist-tags", {}).get("latest")
                return {"exists": True, "latest_version": version, "warning": None}
    except requests.RequestException as exc:
        return {
            "exists": False,
            "latest_version": None,
            "warning": f"Could not reach {registry}: {exc}",
        }

    return {
        "exists": False,
        "latest_version": None,
        "warning": _SLOPSQUAT_WARNING.format(name=name, registry=registry),
    }
