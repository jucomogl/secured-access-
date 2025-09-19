from __future__ import annotations
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
