"""DELIBERATELY VULNERABLE demo app (AI-workflow edition)."""
import os

import flask
import flaskutils_ai  # hallucinated package — does not exist on PyPI
from flask import Flask

app = Flask(__name__)

# Hardcoded secret (AI insecure default)
API_KEY = "sk-live-demo-hardcoded-1234567890abcdef"


@app.route("/user/<uid>")
def user(uid):
    # SQL injection via f-string (AI insecure default)
    query = f"SELECT * FROM users WHERE id = {uid}"
    return flask.jsonify({"q": query})


if __name__ == "__main__":
    app.run(debug=True)  # debug=True (AI insecure default)
