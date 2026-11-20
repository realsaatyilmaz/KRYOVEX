import os
import re
import secrets
import sqlite3
from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "kryovex_scripts.db")


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scripts (
                token TEXT PRIMARY KEY,
                script TEXT NOT NULL,
                provider TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def is_roblox_client(user_agent: str) -> bool:
    if not user_agent:
        return False
    return "roblox" in user_agent.lower()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/save", methods=["POST"])
def api_save():
    data = request.get_json(silent=True) or {}
    script = data.get("script", "")
    provider = data.get("provider", "kryovex")

    if not isinstance(script, str) or not script.strip():
        return jsonify({"error": "Script boş olamaz"}), 400

    token = secrets.token_hex(16)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO scripts (token, script, provider) VALUES (?, ?, ?)",
            (token, script, provider),
        )
        conn.commit()

    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    raw_url = f"{proto}://{host}/v2/scrap/{token}/raw"

    return jsonify({"token": token, "url": raw_url}), 200


@app.route("/v2/scrap/<token>/raw", methods=["GET"])
def scrap_raw(token: str):
    if not re.fullmatch(r"[0-9a-fA-F]{32}", token):
        return Response("404 Not Found!", status=404, mimetype="text/plain")

    ua = request.headers.get("User-Agent", "")
    if not is_roblox_client(ua):
        return Response("404 Not Found!", status=404, mimetype="text/plain")

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT script FROM scripts WHERE token = ?",
            (token.lower(),),
        ).fetchone()

    if not row:
        return Response("404 Not Found!", status=404, mimetype="text/plain")

    return Response(row[0], status=200, mimetype="text/plain; charset=utf-8")


@app.route("/v2/scrap/<path:subpath>", methods=["GET"])
def scrap_block(subpath: str):
    return Response("404 Not Found!", status=404, mimetype="text/plain")


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
