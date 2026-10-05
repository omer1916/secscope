"""Deliberately vulnerable Flask app for SecScope tests. Loopback only. DO NOT DEPLOY."""

import os
import sqlite3
import traceback

import config
import jwt
from flask import Flask, make_response, redirect, request

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "shop.db")

# Serving the project root as static files exposes .env, *.bak, sources...
app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = "supersecretkey123"  # hardcoded secret


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT,
                                          password TEXT, ssn TEXT);
        CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        """
    )
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO users (id, name, email, password, ssn) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "alice", "alice@example.test", "alice123", "111-22-3333"),
                (2, "bob", "bob@example.test", "bob123", "444-55-6666"),
                (3, "admin", "admin@example.test", "admin", "000-00-0000"),
            ],
        )
        conn.executemany(
            "INSERT INTO products (name, price) VALUES (?, ?)",
            [("apple", 1.0), ("banana", 0.5), ("cherry", 3.0)],
        )
    conn.commit()
    conn.close()


@app.after_request
def cors(response):
    origin = request.headers.get("Origin")
    if origin:  # reflects any origin, with credentials
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route("/")
def index():
    return (
        "<html><head><title>Vuln Shop</title></head><body><h1>Vuln Shop</h1>"
        '<form action="/search"><input name="q"><button>Search</button></form>'
        '<a href="/hello?name=guest">hello</a> <a href="/download?file=manual.txt">manual</a>'
        '<form method="post" action="/login"><input name="username"><input name="password" '
        'type="password"><button>Login</button></form></body></html>'
    )


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = db()
    try:
        # SQL injection: string concatenation
        rows = conn.execute(
            "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
        ).fetchall()
    except sqlite3.Error as exc:
        return f"<pre>SQL error: {exc}</pre>", 500
    finally:
        conn.close()
    items = "".join(f"<li>{r['name']} - {r['price']}</li>" for r in rows)
    return f"<html><body><h1>Results for {q}</h1><ul>{items}</ul></body></html>"


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return f"<html><body><h1>Hello {name}!</h1></body></html>"  # reflected XSS


@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"))  # open redirect


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    path = os.path.join(BASE, "files", filename)  # path traversal
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read(), 200, {"Content-Type": "text/plain"}
    except OSError:
        return "not found", 404


@app.route("/login", methods=["POST"])
def login():
    # No rate limiting, no lockout, default admin/admin works.
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = db()
    row = conn.execute(
        "SELECT id, name FROM users WHERE name = ? AND password = ?", (username, password)
    ).fetchone()
    conn.close()
    if row is None:
        return "invalid username or password", 401
    token = jwt.encode(
        {"sub": str(row["id"]), "name": row["name"]}, config.JWT_SECRET, algorithm="HS256"
    )
    resp = make_response({"token": token})
    resp.set_cookie("session_id", f"user-{row['id']}")  # no Secure/HttpOnly/SameSite
    return resp


@app.route("/api/me")
def me():
    auth = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = jwt.decode(auth, config.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return {"error": "unauthorized"}, 401
    return {"user": claims}


@app.route("/api/users/<int:user_id>")
def user(user_id):
    # IDOR: no authorization check; also leaks password and ssn fields.
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if row is None:
        return {"error": "not found"}, 404
    return dict(row)


@app.route("/crash")
def crash():
    try:
        int(request.args.get("n", "x"))
    except ValueError:
        return f"<pre>{traceback.format_exc()}</pre>", 500  # stack trace leak
    return "ok"


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
