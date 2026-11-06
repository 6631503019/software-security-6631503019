"""NoteVault, a local-only Flask note application."""
import hashlib
import hmac
import os
import secrets
import sqlite3
from functools import wraps

import jwt
from flask import Flask, abort, jsonify, make_response, redirect, render_template_string, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
DB = os.environ.get("NOTEvault_DB", "/tmp/notevault.db")
SECRET = os.environ.get("APP_SECRET") or secrets.token_urlsafe(32)
if not os.environ.get("APP_SECRET"):
    app.logger.warning("APP_SECRET is unset; using an ephemeral development secret")
TEAM_ID = os.environ.get("TEAM_ID", "unassigned")
TEAM_SALT = os.environ.get("TEAM_SALT", "notevault-anti-copy-dev-salt")


def team_marker():
    return hmac.new(TEAM_SALT.encode(), TEAM_ID.encode(), hashlib.sha256).hexdigest()[:12]


PAGE = """
<!doctype html><title>NoteVault</title>
{% if user %}<p>Signed in as <b>{{ user }}</b> ·
<form method=post action="/logout"><input type=hidden name=csrf_token value="{{ csrf_token }}"><button>logout</button></form>
{% if is_admin %}· <a href="/admin">admin</a>{% endif %}</p>
<form method=post action="/notes"><input type=hidden name=csrf_token value="{{ csrf_token }}">
<input name=title placeholder=title><input name=body placeholder=note><button>Add note</button></form>
<h3>Your notes</h3><ul>{% for row in notes %}<li>#{{ row['id'] }} <b>{{ row['title'] }}</b>: {{ row['body'] }}</li>{% endfor %}</ul>
<form action="/search"><input name=q placeholder="search notes"><button>Search</button></form>
{% else %}
<form method=post action="/login"><input type=hidden name=csrf_token value="{{ csrf_token }}">
user <input name=username> pass <input name=password type=password><button>Login</button></form>
<form method=post action="/register"><input type=hidden name=csrf_token value="{{ csrf_token }}">
new: <input name=username> <input name=password type=password><button>Register</button></form>
{% endif %}
"""


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def seed():
    con = db()
    con.executescript(
        "DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS notes;"
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
        "password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('user','admin')));"
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL);"
    )
    con.executemany("INSERT INTO users (username, password, role) VALUES (?,?,?)", [
        ("alice", generate_password_hash("alicepw"), "user"),
        ("admin", generate_password_hash("admin123"), "admin"),
    ])
    con.executemany("INSERT INTO notes (owner, title, body) VALUES (?,?,?)", [
        ("alice", "groceries", "milk, eggs"),
        ("admin", "infra", "prod db password is hunter2"),
        ("admin", "build-tag", "team=%s marker=%s" % (TEAM_ID, team_marker())),
    ])
    con.commit()
    con.close()


def current_user():
    token = request.cookies.get("session", "")
    if not token:
        return None
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"]).get("sub")
    except (jwt.InvalidTokenError, TypeError):
        return None


def role_of(username):
    con = db()
    row = con.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    return row["role"] if row else None


def csrf_token():
    return request.cookies.get("csrf_token") or secrets.token_urlsafe(32)


def require_csrf():
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = request.cookies.get("csrf_token")
    token = request.cookies.get("session", "")
    try:
        claims = jwt.decode(token, SECRET, algorithms=["HS256"])
        session_csrf = claims.get("csrf", "")
    except (jwt.InvalidTokenError, TypeError):
        session_csrf = ""
    if (not supplied or not expected or not hmac.compare_digest(supplied, expected)
            or (request.cookies.get("session")
                and (not session_csrf or not hmac.compare_digest(supplied, session_csrf)))):
        abort(403, description="CSRF validation failed")


def request_value(name):
    payload = request.get_json(silent=True) or {}
    return request.form.get(name) or payload.get(name)


def authenticated(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return "auth required", 401
        return view(*args, **kwargs)
    return wrapped


def owned_note(user, nid):
    con = db()
    row = con.execute(
        "SELECT id,owner,title,body FROM notes WHERE id = ? AND owner = ?", (nid, user)
    ).fetchone()
    con.close()
    return row


@app.route("/")
def home():
    user = current_user()
    notes = []
    if user:
        con = db()
        notes = con.execute("SELECT id,title,body FROM notes WHERE owner = ?", (user,)).fetchall()
        con.close()
    token = csrf_token()
    response = make_response(render_template_string(
        PAGE, user=user, is_admin=(user and role_of(user) == "admin"),
        notes=notes, csrf_token=token
    ))
    if not request.cookies.get("csrf_token"):
        response.set_cookie("csrf_token", token, httponly=False, samesite="Lax")
    return response


@app.route("/register", methods=["POST"])
def register():
    require_csrf()
    username = request_value("username")
    password = request_value("password")
    if not username or not password or len(username) > 80 or len(password) < 12:
        return "valid username and password required", 400
    con = db()
    try:
        con.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)", (
            username, generate_password_hash(password), "user"
        ))
        con.commit()
    except sqlite3.IntegrityError:
        return "username already exists", 409
    finally:
        con.close()
    return redirect("/")


@app.route("/login", methods=["POST"])
def login():
    require_csrf()
    username = request_value("username")
    password = request_value("password") or ""
    con = db()
    row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    if not row or not check_password_hash(row["password"], password):
        return "login failed", 401
    csrf = secrets.token_urlsafe(32)
    token = jwt.encode({"sub": username, "csrf": csrf}, SECRET, algorithm="HS256")
    response = make_response(redirect("/"))
    secure = os.environ.get("COOKIE_SECURE") == "1"
    response.set_cookie("session", token, httponly=True, secure=secure, samesite="Lax")
    response.set_cookie("csrf_token", csrf, httponly=False, secure=secure, samesite="Lax")
    return response


@app.route("/logout", methods=["POST"])
@authenticated
def logout():
    require_csrf()
    response = make_response(redirect("/"))
    response.delete_cookie("session")
    response.delete_cookie("csrf_token")
    return response


@app.route("/notes", methods=["POST"])
@authenticated
def add_note():
    require_csrf()
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    if len(title) > 200 or len(body) > 10000:
        return "note too large", 400
    con = db()
    con.execute("INSERT INTO notes (owner,title,body) VALUES (?,?,?)",
                (current_user(), title, body))
    con.commit()
    con.close()
    return redirect("/")


@app.route("/api/notes/<int:nid>")
@authenticated
def api_note(nid):
    row = owned_note(current_user(), nid)
    return jsonify(dict(row)) if row else (jsonify(error="not found"), 404)


@app.route("/search")
@authenticated
def search():
    term = request.args.get("q", "")
    con = db()
    rows = con.execute(
        "SELECT id,title,body FROM notes WHERE owner = ? AND body LIKE ?",
        (current_user(), "%" + term + "%"),
    ).fetchall()
    con.close()
    return render_template_string(
        "<a href='/'>back</a><ul>{% for row in rows %}"
        "<li>{{ row['title'] }}: {{ row['body'] }}</li>{% endfor %}</ul>", rows=rows
    )


@app.route("/admin")
@authenticated
def admin():
    if role_of(current_user()) != "admin":
        return "forbidden", 403
    con = db()
    rows = con.execute("SELECT id,username,role FROM users").fetchall()
    con.close()
    return jsonify([dict(row) for row in rows])


@app.route("/export")
@authenticated
def export():
    fmt = request.args.get("fmt", "txt")
    if fmt not in {"txt", "json"}:
        return "unsupported format", 400
    con = db()
    rows = con.execute(
        "SELECT id,title,body FROM notes WHERE owner = ?", (current_user(),)
    ).fetchall()
    con.close()
    if fmt == "json":
        return jsonify([dict(row) for row in rows])
    return make_response(
        "\n".join("%s: %s" % (row["title"], row["body"]) for row in rows),
        200, {"Content-Type": "text/plain; charset=utf-8"}
    )


if __name__ == "__main__":
    seed()
    app.run(host="0.0.0.0", port=8080, debug=False)
