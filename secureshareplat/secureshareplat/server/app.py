import os
import uuid
import hashlib
import time
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {}
SESSIONS = {}
FILES = {}
LOGS = []

FILES_DIR = os.path.join(os.path.dirname(__file__), "file_store")
os.makedirs(FILES_DIR, exist_ok=True)

def hash_password(password, salt):
    result = hashlib.sha256((password + salt).encode()).hexdigest()
    return result

def make_token(username):
    token = username + ":" + os.urandom(24).hex()
    expires = time.time() + 86400
    SESSIONS[token] = {"username": username, "expires": expires}
    return token

def check_auth():
    token = request.headers.get("X-Auth-Token", "")
    sess = SESSIONS.get(token)
    if not sess:
        return None
    if sess["expires"] < time.time():
        return None
    return sess["username"]

def add_log(username, action, detail):
    LOGS.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": username,
        "action": action,
        "detail": detail
    })

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    pub_key = data.get("dh_public_key", "")

    if not username or not password or not pub_key:
        return jsonify({"error": "All fields required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if username in USERS:
        return jsonify({"error": "Username already taken"}), 409

    salt = os.urandom(16).hex()
    USERS[username] = {
        "password_hash": hash_password(password, salt),
        "salt": salt,
        "dh_public_key": pub_key
    }

    add_log(username, "REGISTER", "New account created")
    token = make_token(username)
    return jsonify({"token": token}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    user = USERS.get(username)
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401

    if hash_password(password, user["salt"]) != user["password_hash"]:
        return jsonify({"error": "Invalid username or password"}), 401

    add_log(username, "LOGIN", "Logged in successfully")
    token = make_token(username)
    return jsonify({"token": token, "dh_public_key": user["dh_public_key"]}), 200

@app.route("/users", methods=["GET"])
def list_users():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    users = [
        {"username": u, "dh_public_key": data["dh_public_key"]}
        for u, data in USERS.items()
    ]
    return jsonify({"users": users}), 200

@app.route("/users/<target>/pubkey", methods=["GET"])
def get_pubkey(target):
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    user = USERS.get(target.lower())
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"dh_public_key": user["dh_public_key"]}), 200

@app.route("/upload", methods=["POST"])
def upload_file():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    recipient = request.form.get("recipient", "").lower()
    filename = request.form.get("original_filename", "file")
    sender_pub = request.form.get("sender_dh_public_key", "")

    if recipient not in USERS:
        return jsonify({"error": "Recipient not found"}), 404
    if "encrypted_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    blob = request.files["encrypted_file"].read()
    file_id = str(uuid.uuid4())
    path = os.path.join(FILES_DIR, file_id + ".enc")

    with open(path, "wb") as f:
        f.write(blob)

    FILES[file_id] = {
        "id": file_id,
        "original_name": filename,
        "sender": username,
        "recipient": recipient,
        "sender_dh_public_key": sender_pub,
        "size_bytes": len(blob),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    add_log(username, "FILE_UPLOAD", f"Sent '{filename}' to {recipient}")
    return jsonify({"file_id": file_id}), 201

@app.route("/files/inbox", methods=["GET"])
def inbox():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    my_files = [f for f in FILES.values() if f["recipient"] == username]
    return jsonify({"files": my_files}), 200

@app.route("/files/sent", methods=["GET"])
def sent_files():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    my_files = [f for f in FILES.values() if f["sender"] == username]
    return jsonify({"files": my_files}), 200

@app.route("/files/<file_id>", methods=["GET"])
def download_file(file_id):
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    meta = FILES.get(file_id)
    if not meta:
        return jsonify({"error": "File not found"}), 404

    if username != meta["sender"] and username != meta["recipient"]:
        return jsonify({"error": "Access denied"}), 403

    path = os.path.join(FILES_DIR, file_id + ".enc")
    with open(path, "rb") as f:
        blob = f.read()

    add_log(username, "FILE_DOWNLOAD", f"Downloaded '{meta['original_name']}'")

    from flask import Response
    return Response(blob, mimetype="application/octet-stream")

@app.route("/logs", methods=["GET"])
def get_logs():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    my_logs = [log for log in LOGS if log["user"] == username]
    return jsonify({"logs": my_logs}), 200

if __name__ == "__main__":
    print("SecureShare Server running on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)