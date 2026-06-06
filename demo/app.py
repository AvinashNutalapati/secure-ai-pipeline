"""
Deliberately-Vulnerable Demo App
=================================
This file contains INTENTIONAL security flaws to demonstrate each gate in the
secure-ai-pipeline. DO NOT deploy this. Every flaw is labeled with the tool
and stage that catches it.

Flaw map
---------
[F1] Hallucinated package import        → Stage 0: check_packages.py (HARD BLOCK)
[F2] Hardcoded API key                  → Stage 0: Gitleaks (HARD BLOCK)
[F3] SQL injection via f-string         → Stage 1: Semgrep rule sql-injection-fstring (BLOCK)
[F4] Flask debug=True                   → Stage 1: Semgrep rule flask-debug-true (BLOCK)
[F5] Wildcard CORS                      → Stage 1: Semgrep rule wildcard-cors (WARN)
[F6] TLS verify=False                   → Stage 1: Semgrep rule tls-verify-false (BLOCK)
[F7] subprocess shell=True              → Stage 1: Semgrep rule subprocess-shell-true (BLOCK)
[F8] Known-CVE dependency (Flask 1.0)   → Stage 1: Trivy SCA (BLOCK on fixable Critical/High)
"""

# [F1] HALLUCINATED PACKAGE — 'flaskutils_ai' does not exist on PyPI.
#      AI models frequently hallucinate plausible-sounding package names.
#      check_packages.py will resolve this against PyPI and exit 1.
import flaskutils_ai  # noqa: F401  ← does not exist

import sqlite3
import subprocess

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS  # Flask-CORS — real package

app = Flask(__name__)

# [F5] WILDCARD CORS — any origin can make credentialed requests.
#      Caught by Semgrep rule 'wildcard-cors' (WARNING).
CORS(app, resources={r"/*": {"origins": "*"}})

# [F2] HARDCODED API KEY — committing credentials in source is the #1 secret leak pattern.
#      Caught by Gitleaks (HARD BLOCK) and Semgrep rule 'hardcoded-api-key'.
API_KEY = "sk-prod-abc123XYZ987secretDoNotCommit"   # noqa: S105

DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/user")
def get_user():
    """
    [F3] SQL INJECTION — username is interpolated directly into the query.
         A request like /user?name=' OR '1'='1 dumps the entire table.
         Caught by Semgrep rule 'sql-injection-fstring' (BLOCK).
         Fix: cursor.execute("SELECT * FROM users WHERE name=?", (name,))
    """
    name = request.args.get("name", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name='{name}'")  # ← F3
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/ping")
def ping():
    """
    [F7] COMMAND INJECTION — host parameter flows directly into shell=True.
         A request like /ping?host=127.0.0.1;cat /etc/passwd executes arbitrary commands.
         Caught by Semgrep rule 'subprocess-shell-true' (BLOCK).
         Fix: subprocess.run(["ping", "-c", "1", host], shell=False)
    """
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # ← F7
    return result.decode()


@app.route("/fetch")
def fetch_url():
    """
    [F6] TLS VERIFICATION DISABLED — allows MITM attacks on outbound requests.
         Caught by Semgrep rule 'tls-verify-false' (BLOCK).
         Fix: Remove verify=False entirely (default is True).
    """
    url = request.args.get("url", "https://example.com")
    resp = requests.get(url, verify=False)  # ← F6  # noqa: S501
    return resp.text


if __name__ == "__main__":
    # [F4] FLASK DEBUG=TRUE — exposes an interactive Werkzeug debugger that
    #      allows arbitrary Python execution via the browser.
    #      Caught by Semgrep rule 'flask-debug-true' (BLOCK).
    #      Fix: Use an env var — debug=os.getenv("FLASK_DEBUG", "false") == "true"
    app.run(host="0.0.0.0", port=5000, debug=True)  # ← F4
