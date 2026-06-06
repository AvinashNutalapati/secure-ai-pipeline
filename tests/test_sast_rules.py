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
]


@pytest.mark.parametrize("rule_id,positive,negative", CASES, ids=[c[0] for c in CASES])
def test_rule_fires_on_positive(tmp_path, rule_id, positive, negative):
    assert rule_id in _rule_ids(tmp_path, positive)


@pytest.mark.parametrize("rule_id,positive,negative", CASES, ids=[c[0] for c in CASES])
def test_rule_silent_on_negative(tmp_path, rule_id, positive, negative):
    assert rule_id not in _rule_ids(tmp_path, negative)
