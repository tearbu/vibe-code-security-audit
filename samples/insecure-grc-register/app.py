"""Deliberately insecure GRC register sample. DO NOT DEPLOY.

I wrote this app to imitate what comes out of a rushed AI coding
session: it works on the first run, and nearly every security decision
is wrong. It holds a small register of risks and controls with
fictional data. It exists so the scanner in this project has something
honest to find, and so the hardened version next door has something to
be compared against.

Known problems, on purpose: a hardcoded secret key, a hardcoded
database password, a hardcoded API token, SQL built by concatenating
strings, debug mode on, binding to every network interface, CORS open
to any origin, no authentication on any route, and no record of who
viewed or changed anything.
"""

import sqlite3

from flask import Flask, redirect, request

app = Flask(__name__)

# The session secret, written straight into the source.
app.config["SECRET_KEY"] = "grc-super-secret-key-12345"

# A database password kept in code because it was quick.
DB_PASSWORD = "P@ssw0rd!for-the-grc-db"

# A token for the "risk intelligence feed" integration.
RISK_FEED_TOKEN = "tok_live_9f8e7d6c5b4a3210"


def get_db():
    conn = sqlite3.connect("grc.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.after_request
def add_cors_headers(response):
    # Let any website call the API. What could go wrong.
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.route("/")
def index():
    return "GRC register: visit /risks to see the register."


@app.route("/risks")
def list_risks():
    owner = request.args.get("owner", "")
    # Build the query by gluing the filter straight into the SQL.
    query = "SELECT * FROM risks WHERE owner = '" + owner + "'"
    rows = get_db().execute(query).fetchall()
    print("listed risks for", owner)
    return {"risks": [dict(row) for row in rows]}


@app.route("/risks/add", methods=["POST"])
def add_risk():
    title = request.form["title"]
    owner = request.form["owner"]
    db = get_db()
    db.execute("INSERT INTO risks (title, owner) VALUES ('" + title + "', '" + owner + "')")
    db.commit()
    print("added risk", title)
    return redirect("/risks")


@app.route("/risks/<risk_id>/delete", methods=["POST"])
def delete_risk(risk_id):
    db = get_db()
    db.execute("DELETE FROM risks WHERE id = " + risk_id)
    db.commit()
    print("deleted risk", risk_id)
    return redirect("/risks")


@app.route("/controls")
def list_controls():
    rows = get_db().execute("SELECT * FROM controls").fetchall()
    return {"controls": [dict(row) for row in rows]}


if __name__ == "__main__":
    # Debug on and reachable from the whole network, the classic combo.
    app.run(host="0.0.0.0", port=5000, debug=True)
