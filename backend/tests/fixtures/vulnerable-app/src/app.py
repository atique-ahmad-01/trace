import os
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# Hard-coded key material imported from source (see settings_dev.py) — intentionally insecure.
from settings_dev import DEPLOY_KEY  # noqa: F401


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/config", methods=["POST"])
def load_config():
    return str(yaml.load(request.data))


@app.route("/eval")
def calc():
    return str(eval(request.args.get("expr")))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
