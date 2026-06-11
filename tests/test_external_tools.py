"""Tests for scripts/external_tools.py — the OSS scanner adapters.

The tools themselves aren't installed in CI, so we test the parsers against
captured sample outputs and confirm each runner degrades to None when its tool
is absent.
"""

import external_tools as ext


def test_detect_returns_known_tools():
    d = ext.detect()
    assert set(d) == {"gitleaks", "semgrep", "trivy", "osv-scanner", "docker"}


def test_norm_sev_aliases():
    assert ext._norm_sev("ERROR") == "HIGH"
    assert ext._norm_sev("warning") == "MEDIUM"
    assert ext._norm_sev("note") == "LOW"
    assert ext._norm_sev("CRITICAL") == "CRITICAL"
    assert ext._norm_sev("weird", default="LOW") == "LOW"


def test_cvss_band():
    assert ext._cvss_band("9.8") == "CRITICAL"
    assert ext._cvss_band("7.0") == "HIGH"
    assert ext._cvss_band("4.0") == "MEDIUM"
    assert ext._cvss_band("0.1") == "LOW"


def test_parse_gitleaks():
    data = [{"Description": "AWS Access Key", "File": "config/prod.env",
             "StartLine": 12, "RuleID": "aws-access-token", "Secret": "AKIA..."}]
    out = ext.parse_gitleaks(data)
    assert len(out) == 1
    assert out[0]["severity"] == "CRITICAL"
    assert out[0]["file"] == "config/prod.env" and out[0]["line"] == 12
    assert out[0]["tool"] == "gitleaks"


def test_parse_sarif_semgrep():
    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "dangerous-eval", "defaultConfiguration": {"level": "error"},
         "help": {"text": "Avoid eval on user input."}}]}},
        "results": [{"ruleId": "dangerous-eval", "level": "error",
                     "message": {"text": "Detected eval on user input"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "app.py"},
                         "region": {"startLine": 10}}}]}]}]}
    out = ext.parse_sarif(sarif, tool="semgrep")
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"            # error → HIGH
    assert out[0]["title"] == "Detected eval on user input"
    assert out[0]["file"] == "app.py" and out[0]["line"] == 10


def test_parse_sarif_uses_cvss_metadata():
    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "r", "properties": {"security-severity": "9.5"},
         "defaultConfiguration": {"level": "warning"}}]}},
        "results": [{"ruleId": "r", "message": {"text": "Critical bug"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "x"}, "region": {"startLine": 1}}}]}]}]}
    out = ext.parse_sarif(sarif)
    assert out[0]["severity"] == "CRITICAL"        # CVSS 9.5 overrides the level


def test_parse_trivy():
    data = {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-1234", "PkgName": "lodash",
         "InstalledVersion": "4.17.0", "FixedVersion": "4.17.21",
         "Severity": "HIGH", "Title": "Prototype pollution"}]}]}
    out = ext.parse_trivy(data)
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"
    assert "lodash" in out[0]["title"] and "CVE-2021-1234" in out[0]["title"]
    assert "4.17.21" in out[0]["fix"]


def test_parse_osv_flags_malicious_as_critical():
    data = {"results": [{"source": {"path": "package-lock.json"}, "packages": [
        {"package": {"name": "evil-pkg", "version": "1.0.0"},
         "vulnerabilities": [{"id": "MAL-2024-0001",
                              "summary": "Malicious package exfiltrates env"}]},
        {"package": {"name": "lodash", "version": "4.17.0"},
         "vulnerabilities": [{"id": "GHSA-xxxx", "summary": "Prototype pollution",
                              "database_specific": {"severity": "HIGH"}}]}]}]}
    out = ext.parse_osv(data)
    by_pkg = {f["title"].split(":")[0]: f for f in out}
    mal = [f for f in out if "MALICIOUS" in f["title"]][0]
    assert mal["severity"] == "CRITICAL"
    assert "evil-pkg" in mal["title"]
    assert "Remove this dependency NOW" in mal["fix"]
    vuln = [f for f in out if "Vulnerable" in f["title"]][0]
    assert vuln["severity"] == "HIGH"


def test_parse_zap_riskcode_to_severity():
    data = {"site": [{"@name": "http://localhost:3000", "alerts": [
        {"alert": "X-Frame-Options Header Not Set", "riskcode": "2",
         "desc": "<p>Missing header</p>", "solution": "<p>Set it</p>",
         "instances": [{"uri": "http://localhost:3000/"}]}]}]}
    out = ext.parse_zap(data)
    assert out[0]["severity"] == "MEDIUM"          # riskcode 2 → MEDIUM
    assert out[0]["title"] == "X-Frame-Options Header Not Set"
    assert "<" not in out[0]["detail"]             # HTML stripped
    assert out[0]["tool"] == "zap"


def test_runners_return_none_when_tool_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(ext, "_which", lambda name: None)
    assert ext.run_gitleaks(tmp_path) is None
    assert ext.run_semgrep(tmp_path) is None
    assert ext.run_trivy(tmp_path) is None
    assert ext.run_osv(tmp_path) is None
    assert ext.run_zap("http://x") is None


def test_socket_hint_only_when_key_set(monkeypatch):
    monkeypatch.delenv("SOCKET_API_KEY", raising=False)
    monkeypatch.delenv("SOCKET_SECURITY_API_KEY", raising=False)
    assert ext.socket_hint() is None
    monkeypatch.setenv("SOCKET_API_KEY", "x")
    monkeypatch.setattr(ext, "_which", lambda name: None)
    assert "socket" in ext.socket_hint().lower()
