"""Deliberately vulnerable Flask app for a SonarQube secure-code-review lab.

LOCAL SCANNING ONLY. Never deploy this anywhere reachable by others.
Every intentional flaw is marked with a `# FLAW:` comment.
"""
import hashlib
import os
import sqlite3

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# FLAW: hardcoded secret key
app.config["SECRET_KEY"] = "s3cr3t-k3y-do-not-share"
# FLAW: hardcoded database password
DB_PASSWORD = "SuperSecret123!"
# FLAW: third-party API key committed to source (fake, never valid)
PAYMENT_API_KEY = "2b7c00eafaf51815af15f19b774f0707b1c61620"

DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)"
    )
    conn.commit()
    conn.close()


def hash_password(password):
    # FLAW: weak hashing (MD5, unsalted) for passwords
    return hashlib.md5(password.encode()).hexdigest()


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
    # FLAW: SQL injection via string-built query
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    row = conn.execute(query).fetchone()
    conn.close()
    return jsonify(user=row)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FLAW: command injection via os.system on user input
    exit_code = os.system("ping -c 1 " + host)
    return jsonify(host=host, reachable=exit_code == 0)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    # FLAW: eval() on user-supplied input
    result = eval(expr)
    return jsonify(result=result)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")
    # FLAW: TLS certificate verification disabled
    resp = requests.get(url, verify=False, timeout=5)
    return jsonify(status=resp.status_code, length=len(resp.content))


if __name__ == "__main__":
    init_db()
    # FLAW: debug mode enabled in production, bound to all interfaces
    app.run(host="0.0.0.0", debug=True)
