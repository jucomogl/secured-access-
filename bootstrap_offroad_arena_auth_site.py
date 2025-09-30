#!/usr/bin/env python3
"""
Bootstrapper: tworzy repo 'offroad_arena_auth_site' z ochroną logowaniem (Flask)
i opcjonalnie kopiuje Twoją prezentację HTML do templates/deck.html.
Użycie:
  python bootstrap_offroad_arena_auth_site.py --html /ścieżka/do/twojej_prezentacji.html
"""

from __future__ import annotations
from logging import root
import argparse, os, pathlib, shutil, zipfile, hashlib, sys
from datetime import date

PROJECT = "offroad_arena_auth_site"

APP_PY = r'''from __future__ import annotations
import os, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, abort
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

load_dotenv()

def env(name: str, default: str | None = None) -> str:
    v = os.getenv(name, default)
    if v is None:
        raise RuntimeError(f"Missing required env var: {name}")
    return v

def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = env("SECRET_KEY", "dev-secret-change-me")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    AUTH_USERNAME = env("AUTH_USERNAME", "admin")
    PASSWORD_HASH = env("PASSWORD_HASH", generate_password_hash("admin"))

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("user") != AUTH_USERNAME:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    @app.route("/")
    def index():
        return redirect(url_for("deck" if session.get("user") == AUTH_USERNAME else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
            return render_template("login.html", csrf_token=token)

        if request.form.get("csrf_token") != session.get("csrf_token"):
            abort(400, "Invalid CSRF token")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == AUTH_USERNAME and check_password_hash(PASSWORD_HASH, password):
            session.clear()
            session["user"] = AUTH_USERNAME
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("deck"))
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
        return render_template("login.html", error="Nieprawidłowy login lub hasło.", csrf_token=token), 401

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/deck")
    @login_required
    def deck():
        return render_template("deck.html")

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    return app

app = create_app()

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == "hash":
        print(generate_password_hash(sys.argv[2]))
    else:
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=False)
'''

REQUIREMENTS = "Flask==3.0.3\npython-dotenv==1.0.1\nWerkzeug==3.0.3\n"
ENV_EXAMPLE = """SECRET_KEY=change-me-please
AUTH_USERNAME=admin
# To generate: python app.py hash your-password
PASSWORD_HASH=
PORT=8000
"""
DOCKERFILE = """# syntax=docker/dockerfile:1
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python","app.py"]
"""
COMPOSE = """services:
  web:
    build: .
    ports:
      - "8000:8000"
    env_file: .env
    restart: unless-stopped
"""
MAKEFILE = """.PHONY: setup dev docker-build docker-up
setup:
\tpython -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
dev:
\tpython app.py
docker-build:
\tdocker build -t offroad_arena_auth_site:local .
docker-up:
\tdocker compose up --build
"""
LOGIN_HTML = """<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Logowanie</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .card{width:100%;max-width:360px;padding:24px;border:1px solid #ddd;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06)}
    h1{font-size:1.25rem;margin:0 0 12px}
    form{display:grid;gap:12px}
    label{display:grid;gap:4px;font-size:.9rem}
    input{padding:10px;border:1px solid #ccc;border-radius:8px;font-size:1rem}
    button{padding:10px 14px;border:0;border-radius:8px;font-weight:600;cursor:pointer;background:#111;color:#fff}
    .error{color:#b00020;font-size:.9rem;margin-bottom:8px}
    .muted{font-size:.85rem;color:#666;text-align:center;margin-top:8px}
  </style>
</head>
<body>
  <div class="card">
    <h1>Wymagane logowanie</h1>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="post" action="/login">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}"/>
      <label>Login
        <input name="username" autocomplete="username" required>
      </label>
      <label>Hasło
        <input name="password" type="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Zaloguj</button>
    </form>
    <div class="muted">Po zalogowaniu trafisz do prezentacji.</div>
  </div>
</body>
</html>
"""
README = """# Offroad Arena — prezentacja chroniona logowaniem

Minimalny serwer **Flask** z formularzem logowania (login + hasło) chroniący Twoją prezentację HTML.

## Szybki start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py hash TwojeHaslo  # skopiuj hash do PASSWORD_HASH w .env
python app.py                  # http://localhost:8000

Docker
cp .env.example .env
docker compose up --build
# http://localhost:8000


Po zalogowaniu treść z templates/deck.html jest serwowana pod /deck.
"""

def write(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def make_zip(root: pathlib.Path, zip_path: pathlib.Path) -> str:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in root.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(root).as_posix())
    h = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    return h

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--html", type=pathlib.Path, help="Ścieżka do Twojego pliku HTML (zostanie skopiowany do templates/deck.html)")
    ap.add_argument("--outdir", type=pathlib.Path, default=pathlib.Path.cwd(), help="Katalog wyjściowy (domyślnie bieżący)")
    args = ap.parse_args()
    print("jestesm tutaj")
    dest = args.outdir / PROJECT
    if dest.exists():
        shutil.rmtree(dest)
        dest.mkdir(parents=True)
        write(dest / "app.py", APP_PY)
        write(dest / "requirements.txt", REQUIREMENTS)
        write(dest / ".env.example", ENV_EXAMPLE)
        write(dest / "Dockerfile", DOCKERFILE)
        write(dest / "docker-compose.yml", COMPOSE)
        write(dest / "Makefile", MAKEFILE)
        write(dest / "README.md", README)
        write(dest / "templates" / "login.html", LOGIN_HTML)
        deck_path = dest / "templates" / "deck.html"
        if args.html and args.html.exists():
            deck_path.write_bytes(args.html.read_bytes())
        else:
            write(deck_path, "<!doctype html><html><body><h1>Podmień mnie na swoją prezentację</h1></body></html>")

        #zip_name = f"{PROJECT}_{date.today().isoformat()}_v1.zip"
        #zip_path = args.outdir / zip_name
        #sha = make_zip(dest, zip_path)


        print("\nSzybki start:")
        print("  python -m venv .venv && . .venv/bin/activate")
        print("  pip install -r requirements.txt")
        print("  cp .env.example .env")
        print("  python app.py hash TwojeHaslo  # wklej hash do PASSWORD_HASH w .env")
        print("  python app.py  # http://localhost:8000")
if __name__ == '__main__':
    main()
