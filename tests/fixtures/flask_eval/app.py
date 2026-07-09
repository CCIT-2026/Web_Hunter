"""Fixture: Flask service with eval() on user input and file upload."""
import pickle, os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/calculate", methods=["POST"])
def calculate():
    expr = request.json.get("expr", "")
    result = eval(expr)  # eval on input
    return jsonify({"result": result})

@app.route("/api/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if f:
        f.save(os.path.join("/tmp", f.filename))  # path from input
    return jsonify({"ok": True})

@app.route("/api/deserialize", methods=["POST"])
def deserialize():
    data = request.data
    obj = pickle.loads(data)  # pickle.loads on input
    return jsonify({"result": str(obj)})

if __name__ == "__main__":
    app.run()
