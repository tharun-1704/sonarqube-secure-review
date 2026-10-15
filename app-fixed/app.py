"""Remediated version of the secure-code-review lab app.

Same endpoints as app-vulnerable/, with every flagged flaw fixed.
"""
import ast
import ipaddress
import os
import re
import sqlite3
# Reviewed: only called below with a fixed argv and shell=False.
import subprocess  # nosec B404

import bcrypt
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# Secrets come from the environment, never from source.
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
DB_PASSWORD = os.environ.get("DB_PASSWORD")

DB_PATH = os.environ.get("DB_PATH", "users.db")

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
ALLOWED_FETCH_URLS = ("https://example.com", "https://www.example.com")


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash BLOB)"
    )
    conn.commit()
    conn.close()


def hash_password(password):
    # bcrypt: salted, deliberately slow KDF.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def is_valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(host))


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, hash_password(password)),
    )
    conn.commit()
    conn.close()
    return jsonify(status="registered")


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    # Parameterized query: user input is never part of the SQL text.
    row = conn.execute(
        "SELECT id, username FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return jsonify(user=row)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not is_valid_host(host):
        return jsonify(error="invalid host"), 400
    # Argument list, no shell: input cannot inject extra commands. Labels may
    # not start with "-", so the host cannot be read as a ping option either.
    # Reviewed: validated host, no shell, ping resolved from PATH on purpose.
    result = subprocess.run(  # nosec B603 B607
        ["ping", "-c", "1", host], shell=False, capture_output=True, timeout=5
    )
    return jsonify(host=host, reachable=result.returncode == 0)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    # literal_eval only accepts Python literals, so no code execution.
    try:
        result = ast.literal_eval(expr)
    except (ValueError, SyntaxError):
        return jsonify(error="only literal values are accepted"), 400
    return jsonify(result=result)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")
    # Fetch the allow-listed constant, never the caller's string, so URL
    # parser tricks cannot redirect the request (SSRF).
    target = next((allowed for allowed in ALLOWED_FETCH_URLS if allowed == url), None)
    if target is None:
        return jsonify(error="url not allowed"), 400
    # TLS verification stays on (the default), made explicit here.
    resp = requests.get(target, verify=True, timeout=5)
    return jsonify(status=resp.status_code, length=len(resp.content))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", debug=False)
