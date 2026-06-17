"""Tests for Phase 3 — ESLint JS/TS SAST (C4), lockfile integrity + malicious
denylist (D4), kube-linter (D5), dedup observability (E5)."""

import json
from pathlib import Path

import scan_all as sa
from scanners import registry as reg
from scanners.sast import eslint_security
from scanners.packages import lockfile_integrity as li


def _w(root, rel, body):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


# ── C4: ESLint security adapter ──────────────────────────────────────────────

def test_c4_eslint_registered_and_parses_security_rules():
    assert "eslint-security" in [a.name for a in reg.adapters_for("sast")]
    data = [{"filePath": "app.js", "messages": [
        {"ruleId": "security/detect-child-process", "severity": 2,
         "message": "child_process", "line": 10},
        {"ruleId": "no-unused-vars", "severity": 1, "message": "style", "line": 2}]}]
    out = eslint_security.parse(data)
    assert len(out) == 1                                # only the security/* rule kept
    assert out[0]["severity"] == "HIGH" and out[0]["cwe_id"] == "78"
    assert out[0]["rule_key"] == "security/detect-child-process"


def test_c4_eslint_returns_none_when_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(eslint_security, "_which", lambda n: None)
    assert eslint_security.run(reg.ScanContext(root=tmp_path)) is None


# ── D4: lockfile integrity + malicious denylist ──────────────────────────────

def test_d4_lockfile_missing_integrity(tmp_path):
    _w(tmp_path, "package-lock.json", json.dumps({"packages": {
        "": {"name": "x"},
        "node_modules/ok": {"resolved": "https://r/ok", "integrity": "sha512-z"},
        "node_modules/bad": {"resolved": "https://r/bad"}}}))
    fs = li.scan(tmp_path)
    assert any(f["rule_key"] == "lockfile-missing-integrity" for f in fs)


def test_d4_clean_lockfile_no_finding(tmp_path):
    _w(tmp_path, "package-lock.json", json.dumps({"packages": {
        "": {"name": "x"},
        "node_modules/ok": {"resolved": "https://r/ok", "integrity": "sha512-z"},
        "node_modules/local": {"link": True}}}))
    assert not any(f["rule_key"] == "lockfile-missing-integrity" for f in li.scan(tmp_path))


def test_d4_malicious_denylist(tmp_path):
    _w(tmp_path, "app.py", "import colourama\nimport requests\n")
    fs = li.scan(tmp_path)
    mal = [f for f in fs if f["rule_key"] == "pkg-known-malicious"]
    assert mal and mal[0]["severity"] == "CRITICAL" and "colourama" in mal[0]["title"]
    # a normal import is NOT flagged
    assert all("requests" not in f["title"] for f in mal)


def test_d4_bundled_dep_not_flagged(tmp_path):
    # Review regression: bundled deps ship in the parent tarball (no own integrity).
    _w(tmp_path, "package-lock.json", json.dumps({"packages": {
        "": {"name": "x"},
        "node_modules/bundled": {"resolved": "https://r/b", "inBundle": True}}}))
    assert not any(f["rule_key"] == "lockfile-missing-integrity" for f in li.scan(tmp_path))


def test_d4_legit_package_not_in_denylist(tmp_path):
    # Review regression: pip-system-certs is a LEGITIMATE package — must not be flagged.
    from scanners.packages.lockfile_integrity import MALICIOUS_DENYLIST
    assert "pip-system-certs" not in MALICIOUS_DENYLIST["pypi"]
    _w(tmp_path, "app.py", "import pip_system_certs\n")
    assert not any(f["rule_key"] == "pkg-known-malicious" for f in li.scan(tmp_path))


def test_c4_eslint_case_insensitive_and_regexp_cwe():
    data = [{"filePath": "a.js", "messages": [
        {"ruleId": "Security/detect-child-process", "severity": 2, "message": "m", "line": 1},
        {"ruleId": "security/detect-non-literal-regexp", "severity": 1, "message": "m", "line": 2}]}]
    out = eslint_security.parse(data)
    assert len(out) == 2                                       # case-insensitive prefix
    by_rule = {f["rule_key"]: f["cwe_id"] for f in out}
    assert by_rule["security/detect-non-literal-regexp"] == "1333"


def test_d4_runs_offline(tmp_path):
    # D4 checks are offline-safe → they appear in the packages layer even offline.
    _w(tmp_path, "app.py", "import colourama\n")
    layer = sa.orchestrate(tmp_path, offline=True, only=["packages"])["layers"]["packages"]
    assert any(f.rule_key == "pkg-known-malicious" for f in layer.findings)


# ── D5: kube-linter ──────────────────────────────────────────────────────────

def test_d5_kube_linter_registered_heavy():
    kl = [a for a in reg.adapters_for("iac") if a.name == "kube-linter"]
    assert kl and kl[0].heavy is True


# ── E5: dedup observability ──────────────────────────────────────────────────

def test_e5_layer_stats_count_merged_duplicates(tmp_path):
    ctx = sa._scan_context(tmp_path, True)
    ext_results = [
        ("trivy", [reg.finding("MEDIUM", "requests — CVE-7", tool="trivy",
                               vuln_id="CVE-7", signature="requests")]),
        ("osv-scanner", [reg.finding("HIGH", "Vuln: requests — CVE-7", tool="osv-scanner",
                                     vuln_id="CVE-7", signature="requests")]),
    ]
    layer = sa._assemble_layer("sca", ext_results, ctx)
    assert layer.stats["raw"] == 2 and layer.stats["merged"] == 1
    assert layer.stats["dropped"] == 1


def test_e5_stats_in_compact_output(tmp_path):
    # The compact view notes when duplicates were merged.
    layer = sa.Layer("sca", "trivy + osv-scanner", [
        sa.ScanFinding("sca", "HIGH", "x", sources=["trivy", "osv-scanner"])],
        stats={"raw": 2, "merged": 1, "dropped": 1})
    result = {"root": str(tmp_path), "tools": {}, "layers": {"sca": layer}}
    txt = sa.render_compact(result, no_color=True)
    assert "duplicate finding(s) merged" in txt
