"""Fixture: Flask service with SQL injection and JWT."""
from flask import Flask, request, jsonify
import sqlite3
import jwt

app = Flask(__name__)
SECRET = "abc123"  # weak secret

@app.route("/api/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    # SQLi sink
    conn = sqlite3.connect("db.sqlite3")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password))
    user = cur.fetchone()
    if user:
        token = jwt.encode({"user": username}, SECRET, algorithm="HS256")
        return jsonify({"token": token})
    return jsonify({"error": "invalid"}), 401

@app.route("/api/profile", methods=["GET"])
def profile():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        data = jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_signature": False})
    except Exception:
        return jsonify({"error": "invalid token"}), 401
    return jsonify({"user": data.get("user")})

if __name__ == "__main__":
    app.run()
