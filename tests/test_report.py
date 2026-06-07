"""Tests for scripts/report.py — HTML rendering of a Blast Radius report."""

import report


def _report(score=42, findings=None):
    return {
        "score": score,
        "grade": "D",
        "counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 1},
        "by_category": {"MCP": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 1}},
        "findings": findings if findings is not None else [
            {"scanner": "mcp", "category": "MCP", "rule_id": "mcp-secret-env",
             "severity": "CRITICAL", "title": "MCP server 'x' receives secrets",
             "detail": "GITHUB_TOKEN passed to server", "fix": "use OAuth",
             "file": "mcp.json", "line": 0},
            {"scanner": "mcp", "category": "MCP", "rule_id": "mcp-server-inventory",
             "severity": "INFO", "title": "server x", "detail": "", "fix": "",
             "file": "mcp.json", "line": 0},
        ],
    }


def test_html_is_self_contained_and_has_score():
    out = report.render_html(_report(score=42))
    assert out.startswith("<!doctype html>")
    assert "<style>" in out and "http" not in out.split("<style>")[0]  # no external head assets
    assert 'class="score">42' in out
    assert "AI Agent Blast Radius" in out


def test_html_renders_findings_but_skips_info():
    out = report.render_html(_report())
    assert "receives secrets" in out
    assert "use OAuth" in out
    # INFO-level inventory rows are not rendered as finding cards
    assert out.count('class="finding"') == 1


def test_html_escapes_user_text():
    out = report.render_html(_report(findings=[
        {"severity": "HIGH", "category": "X", "title": "<script>alert(1)</script>",
         "detail": "a & b", "fix": "x", "file": "f", "line": 1},
    ]))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_clean_report_renders_celebration():
    out = report.render_html({"score": 100, "grade": "A", "counts": {},
                              "by_category": {}, "findings": []})
    assert "No actionable findings" in out
