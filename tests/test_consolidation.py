"""Tests for scripts/scanners/consolidation.py and its wiring into scan_all.

These lock the product's #1 contract: the SAME issue reported by N overlapping
tools collapses to ONE finding (severity = the worst, sources = all N), while two
genuinely different issues stay distinct — across every channel.
"""

import scan_all as sa
from scanners import consolidation as con
from scanners.registry import finding


# ── fingerprint identity per scan type ───────────────────────────────────────

def test_sca_fingerprint_ignores_file_line_keys_on_cve():
    # Trivy (line 0, target path) and the curated built-in (import line, req path)
    # describe the same CVE on the same package → identical fingerprint.
    a = finding("HIGH", "requests 2.18.0 — CVE-2023-32681", file="requirements.txt",
                line=0, tool="trivy", vuln_id="CVE-2023-32681", signature="requests")
    b = finding("MEDIUM", "requests==2.18.0 → CVE-2023-32681", file="requirements.txt",
                line=3, tool="built-in", vuln_id="CVE-2023-32681", signature="requests")
    assert con.fingerprint("sca", a) == con.fingerprint("sca", b)


def test_sca_same_cve_different_package_stays_distinct():
    a = finding("HIGH", "x", vuln_id="CVE-1", signature="pkg-a", tool="trivy")
    b = finding("HIGH", "y", vuln_id="CVE-1", signature="pkg-b", tool="osv-scanner")
    assert con.fingerprint("sca", a) != con.fingerprint("sca", b)


def test_sast_fingerprint_keys_on_cwe_not_wording():
    # semgrep and bandit word the same flaw differently but share CWE + location.
    a = finding("HIGH", "Flask debug=True", file="app.py", line=10, tool="semgrep",
                cwe_id="94", rule_key="flask-debug-true")
    b = finding("MEDIUM", "B201 flask_debug_true", file="app.py", line=10, tool="bandit",
                cwe_id="94", rule_key="B201")
    assert con.fingerprint("sast", a) == con.fingerprint("sast", b)


def test_secrets_same_value_different_file_stays_distinct():
    a = finding("CRITICAL", "AWS key", file="a.env", line=1, signature="deadbeef")
    b = finding("CRITICAL", "AWS key", file="b.env", line=1, signature="deadbeef")
    assert con.fingerprint("secrets", a) != con.fingerprint("secrets", b)


def test_fallback_excludes_severity_so_disputed_severity_still_merges():
    a = finding("HIGH", "same issue", file="x", line=5, tool="t1")
    b = finding("LOW", "same issue", file="x", line=5, tool="t2")
    assert con.fingerprint("sast", a) == con.fingerprint("sast", b)


# ── consolidate: merge + severity MAX + sources ──────────────────────────────

def test_consolidate_collapses_cve_across_five_tools_max_severity():
    tools = [("trivy", "MEDIUM"), ("osv-scanner", "HIGH"), ("grype", "HIGH"),
             ("pip-audit", "HIGH"), ("built-in", "LOW")]
    findings = [finding(sev, f"requests — CVE-9 ({t})", tool=t,
                        vuln_id="CVE-9", signature="requests") for t, sev in tools]
    out = con.consolidate("sca", findings)
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"                 # worst opinion wins
    assert set(out[0]["sources"]) == {t for t, _ in tools}
    assert len(out[0]["sources"]) == 5


def test_consolidate_sast_two_tools_one_finding_confirmed_two():
    a = finding("HIGH", "Flask debug=True", file="app.py", line=10, tool="semgrep", cwe_id="94")
    b = finding("MEDIUM", "debug flag on", file="app.py", line=10, tool="bandit", cwe_id="94")
    out = con.consolidate("sast", [a, b])
    assert len(out) == 1 and out[0]["severity"] == "HIGH"
    assert out[0]["sources"] == ["semgrep", "bandit"]


def test_consolidate_keeps_distinct_issues():
    a = finding("HIGH", "issue one", file="a.py", line=5, tool="semgrep", rule_key="r1")
    b = finding("HIGH", "issue two", file="a.py", line=5, tool="semgrep", rule_key="r2")
    out = con.consolidate("sast", [a, b])
    assert len(out) == 2


def test_consolidate_verified_secret_wins_representative():
    entropy = finding("HIGH", "possible secret", file="x.env", line=12,
                      tool="gitleaks", signature="abc")
    verified = finding("CRITICAL", "VERIFIED AWS key", file="x.env", line=12,
                       tool="trufflehog", signature="abc", confidence="verified")
    out = con.consolidate("secrets", [entropy, verified])
    assert len(out) == 1
    assert out[0]["confidence"] == "verified"
    assert out[0]["title"] == "VERIFIED AWS key"         # verified source's wording
    assert out[0]["severity"] == "CRITICAL"


def test_consolidate_single_finding_gets_sources_from_tool():
    out = con.consolidate("sast", [finding("HIGH", "x", tool="semgrep", cwe_id="94")])
    assert out[0]["sources"] == ["semgrep"]


def test_consolidate_preserves_first_seen_order():
    fs = [finding("HIGH", "B", file="b", line=1, tool="t", rule_key="rb"),
          finding("HIGH", "A", file="a", line=1, tool="t", rule_key="ra")]
    out = con.consolidate("sast", fs)
    assert [o["title"] for o in out] == ["B", "A"]


# ── end-to-end through the orchestrator (_assemble_layer) ─────────────────────

def test_assemble_layer_dedups_across_tools(monkeypatch, tmp_path):
    # Two SCA tools report the same CVE for the same package → one Layer finding.
    from scanners import registry as reg
    ctx = sa._scan_context(tmp_path, offline=True)
    ext_results = [
        ("trivy", [reg.finding("MEDIUM", "requests 2.18.0 — CVE-7", tool="trivy",
                               vuln_id="CVE-7", signature="requests")]),
        ("osv-scanner", [reg.finding("HIGH", "Vulnerable: requests — CVE-7", tool="osv-scanner",
                                     vuln_id="CVE-7", signature="requests")]),
    ]
    layer = sa._assemble_layer("sca", ext_results, ctx)
    sca = [f for f in layer.findings if f.vuln_id == "CVE-7"]
    assert len(sca) == 1
    assert sca[0].severity == "HIGH"
    assert set(sca[0].sources) == {"trivy", "osv-scanner"}


# ── SARIF: one fingerprinted result per consolidated finding ─────────────────

def test_render_sarif_has_partial_fingerprints_and_tools():
    f = sa.ScanFinding("sca", "HIGH", "requests — CVE-7", "d", "req.txt", 0,
                       "upgrade", "trivy", vuln_id="CVE-7", signature="requests",
                       sources=["trivy", "osv-scanner"])
    result = {"layers": {"sca": sa.Layer("sca", "trivy + osv-scanner", [f])}}
    res = sa.render_sarif(result)["runs"][0]["results"][0]
    assert "partialFingerprints" in res
    assert res["partialFingerprints"]["primaryLocationLineHash"]
    assert res["properties"]["tools"] == ["trivy", "osv-scanner"]
    assert "Confirmed by 2 tools" in res["message"]["text"]


def test_render_sarif_fingerprint_stable_across_equal_findings():
    f1 = sa.ScanFinding("sca", "HIGH", "a", "", "x", 0, "", "trivy", vuln_id="CVE-1", signature="p")
    f2 = sa.ScanFinding("sca", "LOW", "b worded differently", "", "y", 9, "", "osv",
                        vuln_id="CVE-1", signature="p")
    assert (con.fingerprint_hash("sca", f1) == con.fingerprint_hash("sca", f2))


# ── hardening (regressions caught in adversarial review) ─────────────────────

def test_consolidate_filters_empty_sources():
    # A finding carrying a stray '' in sources (or a blank tool) must not leak an
    # empty entry into the merged sources list (→ blank tool in CLI/SARIF output).
    out = con.consolidate("sast", [
        finding("HIGH", "x", file="a.py", line=1, tool="semgrep", cwe_id="94",
                sources=["", "semgrep"])])
    assert out[0]["sources"] == ["semgrep"]
    assert "" not in out[0]["sources"]


def test_consolidate_none_severity_defaults_to_info():
    a = {"severity": None, "title": "x", "file": "a", "line": 1, "tool": "t1", "cwe_id": "94"}
    b = {"severity": None, "title": "x", "file": "a", "line": 1, "tool": "t2", "cwe_id": "94"}
    out = con.consolidate("sast", [a, b])
    assert len(out) == 1 and out[0]["severity"] == "INFO"   # never None


def test_fingerprint_robust_to_line_type():
    a = finding("HIGH", "x", file="a.py", line=10, tool="semgrep", cwe_id="94")
    b = {"severity": "HIGH", "title": "x", "file": "a.py", "line": "10",
         "tool": "bandit", "cwe_id": "94"}        # line as string
    assert con.fingerprint("sast", a) == con.fingerprint("sast", b)


def test_sca_empty_vuln_id_falls_back_to_location():
    # When no advisory id could be extracted, identical title+location still merge.
    a = finding("HIGH", "known vulnerability", file="lock", line=0, tool="npm-audit")
    b = finding("MEDIUM", "known vulnerability", file="lock", line=0, tool="osv-scanner")
    out = con.consolidate("sca", [a, b])
    assert len(out) == 1 and set(out[0]["sources"]) == {"npm-audit", "osv-scanner"}


# ── cross-tool identity through the REAL adapter parsers ──────────────────────

def test_sca_adapters_same_cve_consolidate_through_parsers():
    # Trivy (CVE id), OSV (GHSA primary + CVE alias), pip-audit (PYSEC + CVE alias)
    # must all map to the same vuln_id so one advisory on one package = one finding.
    import external_tools as ext
    from scanners.sca import pip_audit
    trivy = ext.parse_trivy({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"PkgName": "requests", "InstalledVersion": "2.18.0", "FixedVersion": "2.31.0",
         "VulnerabilityID": "CVE-2023-32681", "Severity": "MEDIUM"}]}]})
    osv = ext.parse_osv({"results": [{"source": {"path": "requirements.txt"}, "packages": [
        {"package": {"name": "requests", "version": "2.18.0"}, "vulnerabilities": [
            {"id": "GHSA-j8r2-6x86-q33q", "aliases": ["CVE-2023-32681"], "summary": "leak"}]}]}]})
    pa = pip_audit.parse({"dependencies": [{"name": "requests", "version": "2.18.0", "vulns": [
        {"id": "PYSEC-2023-74", "aliases": ["CVE-2023-32681"], "fix_versions": ["2.31.0"]}]}]},
        source="requirements.txt")
    assert trivy[0]["vuln_id"] == osv[0]["vuln_id"] == pa[0]["vuln_id"] == "CVE-2023-32681"
    out = con.consolidate("sca", trivy + osv + pa)
    assert len(out) == 1
    assert set(out[0]["sources"]) == {"trivy", "osv-scanner", "pip-audit"}
    assert out[0]["severity"] == "HIGH"          # pip-audit's HIGH wins


def test_osv_malicious_keeps_mal_id_no_cve_alias():
    import external_tools as ext
    out = ext.parse_osv({"results": [{"source": {"path": "req.txt"}, "packages": [
        {"package": {"name": "evil", "version": "1.0"}, "vulnerabilities": [
            {"id": "MAL-2024-0001", "summary": "malicious"}]}]}]})
    assert out[0]["vuln_id"] == "MAL-2024-0001" and out[0]["severity"] == "CRITICAL"


def test_brakeman_maps_warning_type_to_cwe():
    from scanners.sast import brakeman
    out = brakeman.parse({"warnings": [{"warning_type": "SQL Injection",
        "message": "m", "file": "a.rb", "line": 1, "confidence": "High", "check_name": "SQL"}]})
    assert out[0]["cwe_id"] == "89"


def test_semgrep_sarif_cwe_extraction_from_tags_and_cwe():
    import external_tools as ext
    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "r-tags", "properties": {"tags": ["security", "CWE-89: SQLi"]}},
        {"id": "r-cwe", "properties": {"cwe": ["CWE-79: XSS"]}}]}},
        "results": [
            {"ruleId": "r-tags", "level": "error", "message": {"text": "sqli"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a"}, "region": {"startLine": 1}}}]},
            {"ruleId": "r-cwe", "level": "error", "message": {"text": "xss"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b"}, "region": {"startLine": 2}}}]}]}]}
    out = ext.parse_sarif(sarif, tool="semgrep")
    cwes = {f["rule_key"]: f["cwe_id"] for f in out}
    assert cwes["r-tags"] == "89" and cwes["r-cwe"] == "79"


def test_builtin_canonical_cwe_map_fully_populated():
    # Every canonical rule that declares a CWE must yield a non-empty cwe number,
    # so the built-in SAST fallback dedups against the OSS tools by CWE.
    from scanners.sast.ai_insecure_defaults import RULES
    for r in RULES:
        if r.get("cwe"):
            assert sa._CANON_CWE.get(r["id"]), f"{r['id']}: empty CWE in _CANON_CWE"
