"""
One test per AI-insecure-default rule: a positive example (should fire) and a
negative example (should not fire). Mirrors .semgrep/ai-insecure-defaults.yml.

Findings are sourced from run_pipeline's stage1_sast (SAST) and stage0_secrets
(the hardcoded-credential rule), combined into one set of rule ids.
"""

import pytest

import run_pipeline as rp


def _rule_ids(tmp_path, code):
    src = tmp_path / "snippet.py"
    src.write_text(code, encoding="utf-8")
    ids = {f.rule_id for f in rp.stage1_sast(src)}
    ids |= {f.rule_id for f in rp.stage0_secrets(src)}
    return ids


CASES = [
    (
        "tls-verify-false",
        "requests.get(url, verify=False)\n",
        "requests.get(url)\n",
    ),
    (
        "flask-debug-true",
        "app.run(debug=True)\n",
        "app.run(host='0.0.0.0', port=5000)\n",
    ),
    (
        "wildcard-cors",
        'CORS(app, origins="*")\n',
        'CORS(app, origins=["https://app.example.com"])\n',
    ),
    (
        "subprocess-shell-true",
        'subprocess.check_output(cmd, shell=True)\n',
        'subprocess.check_output(["ping", "-c", "1", host])\n',
    ),
    (
        "sql-injection-fstring",
        'cursor.execute(f"SELECT * FROM users WHERE name=\'{name}\'")\n',
        'cursor.execute("SELECT * FROM users WHERE name=?", (name,))\n',
    ),
    (
        "hardcoded-api-key",
        'api_key = "sk-prod-abc123XYZ987"\n',
        'api_key = os.environ["API_KEY"]\n',
    ),
    (
        "eval-user-input",
        'eval(request.args.get("x"))\n',
        'value = ast.literal_eval(safe_text)\n',
    ),
]


@pytest.mark.parametrize("rule_id,positive,negative", CASES, ids=[c[0] for c in CASES])
def test_rule_fires_on_positive(tmp_path, rule_id, positive, negative):
    assert rule_id in _rule_ids(tmp_path, positive)


@pytest.mark.parametrize("rule_id,positive,negative", CASES, ids=[c[0] for c in CASES])
def test_rule_silent_on_negative(tmp_path, rule_id, positive, negative):
    assert rule_id not in _rule_ids(tmp_path, negative)


def test_semgrep_yaml_has_no_anded_pattern_alternatives():
    """Regression for the dead-rule bug: sibling `- pattern:` alternatives under
    `patterns:` are AND'd by Semgrep and can never all match the same span —
    alternatives must live under `pattern-either:`."""
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent
            / ".semgrep" / "ai-insecure-defaults.yml").read_text(encoding="utf-8")
    for block in re.findall(r"patterns:\n((?:\s+- pattern:[^\n]*\n)+)", text):
        assert block.count("- pattern:") <= 1, (
            "AND'd pattern alternatives found (use pattern-either):\n" + block)
    # The repaired rules must use OR semantics.
    assert text.count("pattern-either:") >= 3
