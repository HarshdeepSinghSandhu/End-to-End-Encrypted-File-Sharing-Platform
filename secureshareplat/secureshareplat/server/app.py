import os
import uuid
import hashlib
import re
import time
from datetime import datetime
from flask import Flask, request, jsonify, Response

from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


USERS    = {}
SESSIONS = {}
FILES    = {}
LOGS     = []

CONTACTS = {}
REQUESTS = {}

FILES_DIR = os.path.join(os.path.dirname(__file__), "file_store")
os.makedirs(FILES_DIR, exist_ok=True)



def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def is_valid_email(email):
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))

def make_token(username):
    token   = username + ":" + os.urandom(24).hex()
    expires = time.time() + 86400
    SESSIONS[token] = {"username": username, "expires": expires}
    return token

def check_auth():
    token = request.headers.get("X-Auth-Token", "")
    sess  = SESSIONS.get(token)
    if not sess or sess["expires"] < time.time():
        return None
    return sess["username"]

def add_log(username, action, detail):

    try:
         forwarded = request.headers.get("X-Forwarded-For", "")
        ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
    except RuntimeError:
        ip = "system"
    LOGS.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user":      username,
        "action":    action,
        "detail":    detail,
        "ip":        ip
    })

@app.route("/")
def home():
    return "SecureShare Server Running 🚀"


@app.route("/register", methods=["POST"])
def register():
    data     = request.get_json()
    username = data.get("username",      "").strip().lower()
    email    = data.get("email",         "").strip().lower()
    password = data.get("password",      "")
    pub_key  = data.get("dh_public_key", "")

    if not username or not email or not password or not pub_key:
        return jsonify({"error": "All fields required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email address"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if username in USERS:
        return jsonify({"error": "Username already taken"}), 409
    for u in USERS.values():
        if u["email"] == email:
            return jsonify({"error": "Email already registered"}), 409

    salt = os.urandom(16).hex()
    USERS[username] = {
        "password_hash": hash_password(password, salt),
        "salt":          salt,
        "email":         email,
        "dh_public_key": pub_key
    }


    CONTACTS[username] = set()
    REQUESTS[username] = set()

    add_log(username, "REGISTER", f"New account created — {email}")
    token = make_token(username)
    return jsonify({"token": token}), 201




@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    user = USERS.get(username)
    if not user:
        add_log(username, "LOGIN_FAILED", f"Failed login — username not found")
        return jsonify({"error": "Invalid username or password"}), 401
    if hash_password(password, user["salt"]) != user["password_hash"]:
        add_log(username, "LOGIN_FAILED", f"Failed login — incorrect password")
        return jsonify({"error": "Invalid username or password"}), 401

    add_log(username, "LOGIN", "Logged in successfully")
    token = make_token(username)
    return jsonify({"token": token, "dh_public_key": user["dh_public_key"]}), 200




@app.route("/users", methods=["GET"])
def list_users():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    users = [{"username": u} for u in USERS]
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



@app.route("/contacts/request/<target>", methods=["POST"])
def send_contact_request(target):

    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    target = target.lower()

    if target == username:
        return jsonify({"error": "Cannot add yourself"}), 400
    if target not in USERS:
        return jsonify({"error": "User not found"}), 404
    if target in CONTACTS.get(username, set()):
        return jsonify({"error": "Already contacts"}), 409
    if username in REQUESTS.get(target, set()):
        return jsonify({"error": "Request already sent"}), 409

    REQUESTS[target].add(username)
    add_log(username, "CONTACT_REQUEST_SENT", f"Sent contact request to {target}")
    add_log(target,   "CONTACT_REQUEST_RECEIVED", f"Received contact request from {username}")
    return jsonify({"message": f"Contact request sent to {target}"}), 200


@app.route("/contacts/accept/<sender>", methods=["POST"])
def accept_contact_request(sender):

    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    sender = sender.lower()

    if sender not in REQUESTS.get(username, set()):
        return jsonify({"error": "No request from this user"}), 404


    REQUESTS[username].discard(sender)
    CONTACTS[username].add(sender)
    CONTACTS[sender].add(username)

    add_log(username, "CONTACT_ACCEPTED", f"Accepted contact request from {sender}")
    add_log(sender,   "CONTACT_ACCEPTED", f"{username} accepted your contact request")
    return jsonify({"message": f"You are now contacts with {sender}"}), 200


@app.route("/contacts", methods=["GET"])
def get_contacts():
    """Return accepted contacts with their public keys."""
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    contacts = []
    for name in CONTACTS.get(username, set()):
        if name in USERS:
            contacts.append({
                "username":      name,
                "dh_public_key": USERS[name]["dh_public_key"]
            })

    return jsonify({"contacts": contacts}), 200


@app.route("/contacts/requests", methods=["GET"])
def get_contact_requests():
    """Return pending contact requests (people who want to add you)."""
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    pending = list(REQUESTS.get(username, set()))
    return jsonify({"requests": pending}), 200



@app.route("/upload", methods=["POST"])
def upload_file():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    recipient  = request.form.get("recipient",            "").lower()
    filename   = request.form.get("original_filename",    "file")
    sender_pub = request.form.get("sender_dh_public_key", "")

    if recipient not in USERS:
        return jsonify({"error": "Recipient not found"}), 404


    if recipient not in CONTACTS.get(username, set()):
        add_log(username, "UPLOAD_BLOCKED", f"Tried to send '{filename}' to {recipient} — not contacts")
        return jsonify({"error": "You are not contacts with this user. "
                                 "Send them a contact request first."}), 403

    if "encrypted_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    blob    = request.files["encrypted_file"].read()
    file_id = str(uuid.uuid4())
    path    = os.path.join(FILES_DIR, file_id + ".enc")

    with open(path, "wb") as f:
        f.write(blob)

    FILES[file_id] = {
        "id":                   file_id,
        "original_name":        filename,
        "sender":               username,
        "recipient":            recipient,
        "sender_dh_public_key": sender_pub,
        "size_bytes":           len(blob),
        "timestamp":            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    return Response(blob, mimetype="application/octet-stream")



@app.route("/logs", methods=["GET"])
def get_logs():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    # Each user sees only their own logs
    my_logs = [log for log in LOGS if log["user"] == username]
    return jsonify({"logs": my_logs}), 200



if __name__ == "__main__":
    print("SecureShare Server running on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
