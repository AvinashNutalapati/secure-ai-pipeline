"""Tests for the Sprint 2 scanners: prompt_privacy and secrets_in_config."""

import json

from scanners import prompt_privacy, secrets_in_config


def _w(tmp_path, rel, body):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


def _ids(findings):
    return {f.rule_id for f in findings}


# ── prompt_privacy ───────────────────────────────────────────────────────────

def test_prompt_privacy_flags_url_ip_email_secret(tmp_path):
    _w(tmp_path, ".cursorrules",
       "Deploy to https://api.acme.internal\n"
       "DB host 10.1.2.3\n"
       "Email ops@acme.internal\n"
       "Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")
    ids = _ids(prompt_privacy.scan(tmp_path))
    assert {"prompt-internal-url", "prompt-private-ip", "prompt-email",
            "prompt-secret"} <= ids


def test_prompt_privacy_ignores_example_email_and_public_url(tmp_path):
    _w(tmp_path, "AGENTS.md",
       "Contact support@example.com and read https://github.com/acme/repo\n")
    assert prompt_privacy.scan(tmp_path) == []


def test_prompt_privacy_scans_claude_md(tmp_path):
    _w(tmp_path, "CLAUDE.md", "Internal host: 192.168.1.50\n")
    assert "prompt-private-ip" in _ids(prompt_privacy.scan(tmp_path))


# ── secrets_in_config ────────────────────────────────────────────────────────

def test_env_secret_named_value_flagged(tmp_path):
    _w(tmp_path, ".env", "API_TOKEN=s3cr3tValue1234567\nPUBLIC_URL=https://x.com\n")
    ids = _ids(secrets_in_config.scan(tmp_path))
    assert "env-hardcoded-secret" in ids


def test_env_ignores_env_refs_and_placeholders(tmp_path):
    _w(tmp_path, ".env",
       "API_TOKEN=${API_TOKEN}\nDB_PASSWORD=changeme\nSECRET_KEY=your-secret-here\n")
    assert secrets_in_config.scan(tmp_path) == []


def test_env_example_is_skipped(tmp_path):
    _w(tmp_path, ".env.example", "API_TOKEN=s3cr3tValue1234567\n")
    assert secrets_in_config.scan(tmp_path) == []


def test_config_hardcoded_token_is_critical(tmp_path):
    _w(tmp_path, "mcp.json", json.dumps({"mcpServers": {
        "gh": {"command": "x", "env": {"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}},
    }}))
    findings = secrets_in_config.scan(tmp_path)
    assert any(f.rule_id == "config-hardcoded-secret" and f.severity == "CRITICAL"
               for f in findings)


def test_config_env_reference_not_flagged(tmp_path):
    _w(tmp_path, "mcp.json", json.dumps({"mcpServers": {
        "gh": {"command": "x", "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
    }}))
    assert secrets_in_config.scan(tmp_path) == []
