"""
Tiny sample web app for Week 1 threat modeling.
You will NOT exploit this in Week 1 — you will draw a data-flow diagram
and apply STRIDE to its components (web client, app, SQLite DB, /upload).
"""
from flask import Flask, request, jsonify, send_from_directory
import sqlite3, os, uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
DB = "notes.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {".txt", ".md", ".png", ".jpg", ".jpeg", ".pdf"}

def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    con.commit(); con.close()

@app.route("/notes", methods=["GET", "POST"])
def notes():
    con = sqlite3.connect(DB)
    if request.method == "POST":
        owner = request.json.get("owner", "anon")
        body = request.json.get("body", "")
        con.execute("INSERT INTO notes (owner, body) VALUES (?, ?)", (owner, body))
        con.commit()
    rows = con.execute("SELECT id, owner, body FROM notes").fetchall()
    con.close()
    return jsonify(rows)

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]

    ext = os.path.splitext(f.filename or "")[1].lower()

    if ext not in ALLOWED_EXT:
        return {"error": "unsupported file type"}, 400

    safe_client_name = secure_filename(f.filename or "")

    if not safe_client_name:
        return {"error": "invalid filename"}, 400

    server_name = f"{uuid.uuid4().hex}{ext}"

    save_path = os.path.abspath(
        os.path.join(UPLOAD_DIR, server_name)
    )

    base_path = os.path.abspath(UPLOAD_DIR) + os.sep

    if not save_path.startswith(base_path):
        return {"error": "invalid path"}, 400

    f.save(save_path)

    return {"saved": server_name}

@app.route("/files/<name>")
def files(name):
    return send_from_directory(UPLOAD_DIR, name)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
