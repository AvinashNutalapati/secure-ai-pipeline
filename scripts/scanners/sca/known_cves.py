"""
SCA — curated CVE data for pinned dependency versions, keyed by
(normalised_package_name, version). The single source for the offline CVE
checks (run_pipeline.py → npx scan, and mirrored by the MCP server). The
authoritative scan in CI is Trivy; this list backs the no-network local path.

Edit entries here to extend offline CVE coverage.

stdlib only.
"""

KNOWN_CVES = {
    ("flask", "1.0"): [
        {"id": "CVE-2023-30861", "severity": "HIGH", "fixed": "2.3.2",
         "desc": "Flask session cookie not invalidated on logout — session fixation."},
        {"id": "CVE-2018-1000656", "severity": "HIGH", "fixed": "0.12.3",
         "desc": "Werkzeug (Flask dep) debug console PIN bypass — remote code execution."},
    ],
    ("requests", "2.18.0"): [
        {"id": "CVE-2023-32681", "severity": "MEDIUM", "fixed": "2.31.0",
         "desc": "Proxy-Authorization header leaked to third-party hosts on redirect."},
    ],
    ("flask_cors", "3.0.10"): [
        {"id": "CVE-2024-6221", "severity": "MEDIUM", "fixed": "4.0.0",
         "desc": "CORS policy bypass via crafted Origin header."},
    ],
}
