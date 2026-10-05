"""Secure counterpart of vuln-flask: used to measure false positives."""

import os
import secrets
import sqlite3
import time
from html import escape

from flask import Flask, abort, jsonify, request

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "shop.db")

app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

_attempts: dict[str, list[float]] = {}


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)"
    )
    if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO products (name, price) VALUES (?, ?)",
            [("apple", 1.0), ("banana", 0.5), ("cherry", 3.0)],
        )
    conn.commit()
    conn.close()


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers.pop("Server", None)
    return response


@app.route("/")
def index():
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Clean Shop</title></head><body><main><h1>Clean Shop</h1>"
        '<form action="/search"><label>Search <input name="q"></label>'
        "<button>Search</button></form></main></body></html>"
    )


@app.route("/search")
def search():
    q = request.args.get("q", "")[:100]
    conn = db()
    rows = conn.execute(
        "SELECT name, price FROM products WHERE name LIKE ?", (f"%{q}%",)
    ).fetchall()
    conn.close()
    items = "".join(f"<li>{escape(r['name'])} - {r['price']:.2f}</li>" for r in rows)
    return f'<!doctype html><html lang="en"><body><h1>Results for {escape(q)}</h1><ul>{items}</ul></body></html>'


@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr or "?"
    now = time.monotonic()
    recent = [t for t in _attempts.get(ip, []) if now - t < 60]
    if len(recent) >= 5:
        abort(429)
    _attempts[ip] = [*recent, now]
    return jsonify(error="invalid credentials"), 401


@app.errorhandler(404)
def not_found(_e):
    return jsonify(error="not found"), 404


@app.errorhandler(500)
def server_error(_e):
    return jsonify(error="internal error"), 500


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
