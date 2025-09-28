import os
import base64
import json
import hashlib
from pathlib import Path
from flask import Flask, request, redirect, url_for, render_template, send_file, flash, session
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from io import BytesIO

# Load env
load_dotenv()  # loads .env file if present

# Configuration
UPLOAD_FOLDER = Path("uploads_encrypted")
UPLOAD_FOLDER.mkdir(exist_ok=True)
ALLOWED_EXT = None
MASTER_KEY_B64 = os.getenv("MASTER_KEY_B64")
API_TOKEN = os.getenv("API_TOKEN", "mysecrettoken123")

if not MASTER_KEY_B64:
    raise SystemExit("MASTER_KEY_B64 not set in environment. Generate and set before running.")

MASTER_KEY = base64.b64decode(MASTER_KEY_B64)
if len(MASTER_KEY) != 32:
    raise SystemExit("MASTER_KEY_B64 must decode to 32 bytes (AES-256).")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", os.urandom(16))
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB max

# Encryption helpers
def encrypt_bytes(plaintext: bytes, associated_data: bytes = None) -> bytes:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ct

def decrypt_bytes(payload: bytes, associated_data: bytes = None) -> bytes:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = payload[:12]
    ct = payload[12:]
    return aesgcm.decrypt(nonce, ct, associated_data)

def compute_sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ------------------ AUTH ------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        token = request.form.get("token")
        if token == API_TOKEN:
            session["authenticated"] = True
            return redirect(url_for("index"))
        else:
            flash("Invalid token", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))

# -------------- FILE PORTAL ---------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("No file selected", "danger")
            return redirect(url_for("index"))

        orig_name = secure_filename(f.filename)
        data = f.read()

        # Optional: enforce allowed extensions
        if ALLOWED_EXT:
            if "." in orig_name:
                ext = orig_name.rsplit(".", 1)[1].lower()
                if ext not in ALLOWED_EXT:
                    flash("File type not allowed", "danger")
                    return redirect(url_for("index"))

        # compute hash for integrity check
        sha_before = compute_sha256(data)

        # unique safe id
        safe_id = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
        enc_filename = f"{safe_id}.enc"
        meta = {
            "original_filename": orig_name,
            "sha256": sha_before,
            "size": len(data)
        }

        # encrypt & save
        payload = encrypt_bytes(data)
        with open(UPLOAD_FOLDER / enc_filename, "wb") as fh:
            fh.write(payload)
        with open(UPLOAD_FOLDER / f"{safe_id}.meta.json", "w") as fh:
            json.dump(meta, fh)

        flash(f"File uploaded and encrypted as id: {safe_id}", "success")
        return redirect(url_for("index"))

    # GET: list files
    files = []
    for m in UPLOAD_FOLDER.glob("*.meta.json"):
        sid = m.name.replace(".meta.json", "")  # ✅ fixed id
        try:
            meta = json.loads(m.read_text())
            files.append({"id": sid, **meta})
        except Exception:
            continue
    return render_template("index.html", files=files)

    # GET: show uploaded files
    files = []
    for m in UPLOAD_FOLDER.glob("*.meta.json"):
        sid = m.stem
        try:
            meta = json.loads(m.read_text())
            files.append({"id": sid, **meta})
        except Exception:
            continue
    return render_template("index.html", files=files)

@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    if not file_id.isalnum() and "-" not in file_id and "_" not in file_id:
        flash("Invalid file id", "danger")
        return redirect(url_for("index"))

    meta_path = UPLOAD_FOLDER / f"{file_id}.meta.json"
    enc_path = UPLOAD_FOLDER / f"{file_id}.enc"
    if not meta_path.exists() or not enc_path.exists():
        flash("File not found", "danger")
        return redirect(url_for("index"))

    meta = json.loads(meta_path.read_text())
    payload = enc_path.read_bytes()
    try:
        plaintext = decrypt_bytes(payload)
    except Exception:
        flash("Decryption failed or file tampered with", "danger")
        return redirect(url_for("index"))

    sha_after = compute_sha256(plaintext)
    ok = (sha_after == meta.get("sha256"))

    bio = BytesIO(plaintext)
    bio.seek(0)
    download_name = meta.get("original_filename", f"{file_id}.bin")
    response = send_file(
        bio,
        as_attachment=True,
        download_name=download_name,
        mimetype="application/octet-stream"
    )
    response.headers["X-File-Integrity"] = "OK" if ok else "FAILED"
    return response

if __name__ == "__main__":
    app.run(ssl_context="adhoc", host="127.0.0.1", port=5000, debug=True)
