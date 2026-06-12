"""Tests for the OSS tool adapters under scripts/scanners/<type>/.

The binaries aren't installed in CI, so we test each parser against a captured
sample of the tool's real output, and confirm runners degrade to None/[] when
the tool is absent. The registry's discovery + availability is tested too.
"""

from pathlib import Path

from scanners import registry as reg
from scanners.ci_cd import actionlint, zizmor
from scanners.iac import checkov
from scanners.packages import guarddog
from scanners.sast import bandit, gosec
from scanners.sca import grype, pip_audit
from scanners.secrets import detect_secrets, trufflehog


# ── registry ─────────────────────────────────────────────────────────────────

def test_registry_discovers_every_scan_type():
    by_type = {t: [a.name for a in reg.adapters_for(t)] for t in reg.SCAN_TYPE_KEYS}
    assert "trufflehog" in by_type["secrets"] and "gitleaks" in by_type["secrets"]
    assert "guarddog" in by_type["packages"]
    assert {"trivy", "osv-scanner", "grype", "pip-audit"} <= set(by_type["sca"])
    assert {"semgrep", "bandit", "gosec"} <= set(by_type["sast"])
    assert "checkov" in by_type["iac"]
    assert {"zizmor", "actionlint"} <= set(by_type["ci_cd"])
    assert "zap" in by_type["dast"]


def test_adapter_availability_uses_binary_on_path():
    a = reg.ToolAdapter("ghost", "sast", run=lambda ctx: None,
                        binary="definitely-not-a-real-binary-xyz")
    assert a.available() is False
    b = reg.ToolAdapter("always", "sast", run=lambda ctx: None,
                        available_fn=lambda: True)
    assert b.available() is True


def test_guarddog_is_marked_heavy():
    gd = [a for a in reg.adapters_for("packages") if a.name == "guarddog"][0]
    assert gd.heavy is True


def test_available_adapters_excludes_heavy_unless_requested():
    fake = reg.ToolAdapter("fake-heavy-xyz", "sast", run=lambda c: [],
                           available_fn=lambda: True, heavy=True)
    reg.register(fake)
    try:
        with_heavy = [a.name for a in reg.available_adapters("sast", include_heavy=True)]
        without = [a.name for a in reg.available_adapters("sast", include_heavy=False)]
        assert "fake-heavy-xyz" in with_heavy
        assert "fake-heavy-xyz" not in without
    finally:
        reg._ADAPTERS.pop("fake-heavy-xyz", None)


def test_register_rejects_unknown_scan_type():
    import pytest
    with pytest.raises(ValueError):
        reg.register(reg.ToolAdapter("x", "not-a-type", run=lambda ctx: None))


def test_finding_normalises_severity():
    f = reg.finding("error", "t", tool="x")
    assert f["severity"] == "HIGH" and f["tool"] == "x" and f["line"] == 0


def test_runners_return_none_when_tool_missing(monkeypatch, tmp_path):
    # Every adapter checks _which on its own module import of external_tools.
    for mod in (trufflehog, detect_secrets, grype, pip_audit, bandit, gosec,
                guarddog, checkov, zizmor, actionlint):
        monkeypatch.setattr(mod, "_which", lambda name: None)
    ctx = reg.ScanContext(root=tmp_path)
    for mod in (trufflehog, detect_secrets, grype, pip_audit, bandit, gosec,
                guarddog, checkov, zizmor, actionlint):
        assert mod.run(ctx) is None, f"{mod.__name__} should degrade to None"


# ── secrets ──────────────────────────────────────────────────────────────────

def test_trufflehog_verified_is_critical():
    ndjson = (
        '{"SourceMetadata":{"Data":{"Filesystem":{"file":"prod.env","line":12}}},'
        '"DetectorName":"AWS","Verified":true,"Raw":"AKIA"}\n'
        '{"SourceMetadata":{"Data":{"Filesystem":{"file":"app.py","line":5}}},'
        '"DetectorName":"Github","Verified":false}\n'
        'not-json-log-line\n'
    )
    out = trufflehog.parse(ndjson)
    assert len(out) == 2
    aws = [f for f in out if "AWS" in f["title"]][0]
    assert aws["severity"] == "CRITICAL" and aws["file"] == "prod.env" and aws["line"] == 12
    gh = [f for f in out if "Github" in f["title"]][0]
    assert gh["severity"] == "HIGH" and gh["tool"] == "trufflehog"


def test_detect_secrets_parses_results_map():
    data = {"results": {
        "app.py": [{"type": "Secret Keyword", "line_number": 3, "is_verified": False}],
        "x.env": [{"type": "AWS Access Key", "line_number": 1, "is_verified": True}]}}
    out = detect_secrets.parse(data)
    assert len(out) == 2
    verified = [f for f in out if f["file"] == "x.env"][0]
    assert verified["severity"] == "CRITICAL"
    assert all(f["tool"] == "detect-secrets" for f in out)


# ── sca ──────────────────────────────────────────────────────────────────────

def test_grype_parses_match_with_fix():
    data = {"matches": [{
        "vulnerability": {"id": "CVE-2021-1", "severity": "High", "description": "bad",
                          "fix": {"versions": ["1.2.3"], "state": "fixed"}},
        "artifact": {"name": "lodash", "version": "1.0.0",
                     "locations": [{"path": "package-lock.json"}]}}]}
    out = grype.parse(data)
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH" and "lodash" in out[0]["title"]
    assert "1.2.3" in out[0]["fix"] and out[0]["file"] == "package-lock.json"


def test_pip_audit_both_output_shapes():
    newer = {"dependencies": [{"name": "flask", "version": "1.0", "vulns": [
        {"id": "PYSEC-1", "fix_versions": ["1.0.1"], "description": "bug",
         "aliases": ["CVE-2019-1"]}]}]}
    out = pip_audit.parse(newer, source="requirements.txt")
    assert out[0]["severity"] == "HIGH" and "1.0.1" in out[0]["fix"]
    assert out[0]["file"] == "requirements.txt"
    older = [{"name": "jinja2", "version": "2.0", "vulns": [
        {"id": "PYSEC-2", "fix_versions": [], "description": "x"}]}]
    out2 = pip_audit.parse(older)
    assert out2[0]["severity"] == "HIGH" and "No fixed version" in out2[0]["fix"]


# ── sast ─────────────────────────────────────────────────────────────────────

def test_bandit_parses_results():
    data = {"results": [{
        "filename": "app.py", "line_number": 10, "issue_severity": "HIGH",
        "issue_confidence": "HIGH", "issue_text": "subprocess call with shell=True",
        "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true",
        "more_info": "https://bandit.example/B602"}]}
    out = bandit.parse(data)
    assert out[0]["severity"] == "HIGH" and out[0]["file"] == "app.py"
    assert out[0]["line"] == 10 and "B602" in out[0]["title"]
    assert out[0]["fix"].startswith("https://")


def test_gosec_handles_string_and_range_lines():
    data = {"Issues": [
        {"severity": "MEDIUM", "confidence": "HIGH", "cwe": {"id": "22"},
         "rule_id": "G304", "details": "file inclusion", "file": "main.go", "line": "42"},
        {"severity": "LOW", "rule_id": "G104", "details": "errcheck",
         "file": "x.go", "line": "10-12"}]}
    out = gosec.parse(data)
    assert out[0]["line"] == 42 and "G304" in out[0]["title"]
    assert out[1]["line"] == 10            # range "10-12" → start line
    assert all(f["tool"] == "gosec" for f in out)


# ── packages ─────────────────────────────────────────────────────────────────

def test_guarddog_rule_severity_and_skips_clean():
    data = [
        {"package": "evil", "version": "1.0", "issues": 2, "path": "requirements.txt",
         "results": {"exec-base64": [{"message": "base64 exec"}],
                     "typosquatting": [{"message": "looks like requests"}]}},
        {"package": "safe", "version": "2.0", "issues": 0, "results": {}, "path": None}]
    out = guarddog.parse(data)
    assert len(out) == 2                    # only the package with issues
    crit = [f for f in out if "exec-base64" in f["title"]][0]
    assert crit["severity"] == "CRITICAL"
    typo = [f for f in out if "typosquatting" in f["title"]][0]
    assert typo["severity"] == "HIGH" and typo["tool"] == "guarddog"


# ── iac ──────────────────────────────────────────────────────────────────────

def test_checkov_dict_and_multiframework_list():
    one = {"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_20", "check_name": "S3 public access",
         "file_path": "/main.tf", "file_line_range": [1, 5],
         "resource": "aws_s3_bucket.x", "severity": "HIGH",
         "guideline": "https://docs.example/s3"}]}}
    out = checkov.parse(one)
    assert out[0]["severity"] == "HIGH" and out[0]["file"] == "main.tf"  # leading / stripped
    assert out[0]["line"] == 1 and "CKV_AWS_20" in out[0]["title"]
    multi = [
        {"check_type": "dockerfile", "results": {"failed_checks": [
            {"check_id": "CKV_DOCKER_2", "check_name": "healthcheck",
             "file_path": "Dockerfile", "file_line_range": [1, 1], "resource": "x"}]}},
        {"check_type": "terraform", "results": {"failed_checks": []}}]
    out2 = checkov.parse(multi)
    assert len(out2) == 1 and out2[0]["severity"] == "MEDIUM"  # no severity → default


# ── ci_cd ────────────────────────────────────────────────────────────────────

def test_zizmor_parses_sarif():
    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "template-injection", "defaultConfiguration": {"level": "error"}}]}},
        "results": [{"ruleId": "template-injection", "level": "error",
                     "message": {"text": "template injection in run:"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": ".github/workflows/ci.yml"},
                         "region": {"startLine": 20}}}]}]}]}
    out = zizmor.parse(sarif)
    assert out[0]["severity"] == "HIGH" and out[0]["tool"] == "zizmor"
    assert out[0]["file"] == ".github/workflows/ci.yml" and out[0]["line"] == 20


def test_actionlint_bumps_injection_to_high():
    data = [
        {"message": "property injection: ${{ github.event.issue.title }} in run",
         "filepath": ".github/workflows/ci.yml", "line": 15, "column": 9,
         "kind": "expression"},
        {"message": "unexpected key 'foo'", "filepath": ".github/workflows/x.yml",
         "line": 3, "column": 1, "kind": "syntax-check"}]
    out = actionlint.parse(data)
    assert out[0]["severity"] == "HIGH"     # injection → HIGH
    assert out[1]["severity"] == "MEDIUM"   # plain syntax → MEDIUM
    assert out[0]["line"] == 15 and out[0]["tool"] == "actionlint"
