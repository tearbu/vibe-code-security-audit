"""Hardened GRC register sample.

This is the same register as the insecure sample next door, rebuilt
the way I would want it reviewed: secrets come from the environment,
every query is parameterized, every route except the login page
requires a signed-in user, changes are written to an audit log, debug
mode is off, and the server binds to localhost only.

The data is fictional. The app is a teaching sample, not a product.
"""

import logging
import os
import sqlite3
from functools import wraps

from flask import Flask, redirect, request, session
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Secrets come from the environment. If they are missing, the app
# refuses to start instead of falling back to a value in the code.
app.secret_key = os.environ["GRC_SECRET_KEY"]
DB_PATH = os.environ.get("GRC_DB_PATH", "grc.db")

# Audit logging: sign-ins, views, changes and deletions are recorded
# with the acting user, so there is a trail to review later.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
audit_log = logging.getLogger("grc.audit")

# CORS is limited to the one internal site that needs API access.
ALLOWED_ORIGIN = "https://grc.internal.example"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            audit_log.info("anonymous request turned away from %s", request.path)
            return redirect("/login")
        return view(*args, **kwargs)

    return wrapped


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        form_password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row and check_password_hash(row["password_hash"], form_password):
            session["user"] = username
            audit_log.info("sign-in succeeded for %s", username)
            return redirect("/risks")
        audit_log.info("sign-in failed for %s", username)
    return "Login page"


@app.route("/")
@login_required
def index():
    return "GRC register: visit /risks to see the register."


@app.route("/risks")
@login_required
def list_risks():
    owner = request.args.get("owner", "")
    rows = get_db().execute(
        "SELECT * FROM risks WHERE owner = ?", (owner,)
    ).fetchall()
    audit_log.info("%s listed risks for owner %s", session["user"], owner)
    return {"risks": [dict(row) for row in rows]}


@app.route("/risks/add", methods=["POST"])
@login_required
def add_risk():
    title = request.form["title"]
    owner = request.form["owner"]
    db = get_db()
    db.execute(
        "INSERT INTO risks (title, owner) VALUES (?, ?)", (title, owner)
    )
    db.commit()
    audit_log.info("%s added risk %s", session["user"], title)
    return redirect("/risks")


@app.route("/risks/<risk_id>/delete", methods=["POST"])
@login_required
def delete_risk(risk_id):
    db = get_db()
    db.execute("DELETE FROM risks WHERE id = ?", (risk_id,))
    db.commit()
    audit_log.info("%s deleted risk %s", session["user"], risk_id)
    return redirect("/risks")


@app.route("/controls")
@login_required
def list_controls():
    rows = get_db().execute("SELECT * FROM controls").fetchall()
    audit_log.info("%s listed controls", session["user"])
    return {"controls": [dict(row) for row in rows]}


if __name__ == "__main__":
    # Debug off, localhost only. A real deployment would sit behind a
    # proper web server and TLS.
    app.run(host="127.0.0.1", port=5000, debug=False)
