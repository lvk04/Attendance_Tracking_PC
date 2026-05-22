"""
Flask Web Application for Face Recognition Attendance Tracking.

Uses:
- YuNet for face detection
- ArcFace for face recognition
- SQLite for local storage
- Browser webcam via JavaScript getUserMedia
"""

import os
import cv2
import numpy as np
import base64
import sqlite3
import shutil
import glob
import time
from datetime import datetime

from flask import Flask, render_template, request, jsonify

from face_detection import FaceDetector
from arcface_recognizer import ArcFaceRecognizer

import sys

# ── Path resolution (supports PyInstaller bundle) ─────────────────────────────
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
    EXE_DIR  = os.path.dirname(sys.executable)
    DATA_DIR = os.path.join(EXE_DIR, "data")
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, "data")

app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, "templates"),
            static_folder=os.path.join(BASE_DIR, "static"))

FACES_DIR    = os.path.join(DATA_DIR, "registered_faces")
FACES_DB     = os.path.join(DATA_DIR, "faces.db")
ATTENDANCE_DB = os.path.join(DATA_DIR, "attendance.db")

os.makedirs(FACES_DIR, exist_ok=True)
os.makedirs(DATA_DIR,  exist_ok=True)

# ── Initialize Engines ────────────────────────────────────────────────────────
detector   = FaceDetector()
recognizer = ArcFaceRecognizer()
recognizer.load_database(DATA_DIR)

# ── Server-side State ─────────────────────────────────────────────────────────
reg_sessions = {}

recog_state = {
    "tracking_name":     None,
    "consecutive_matches": 0,
    "required_matches":  3,
    "recently_logged":   {},
    "log_cooldown":      10.0,
}

# Syncer reference — set in __main__, used by delete route
_syncer = None


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def decode_base64_image(data_url):
    try:
        if "," in data_url:
            data_url = data_url.split(",", 1)[1]
        img_bytes = base64.b64decode(data_url)
        arr = np.frombuffer(img_bytes, dtype=np.uint8)
        return cv2.imdecode(arr, cv2.IMREAD_COLOR)
    except Exception as e:
        print(f"Image decode error: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/recognize")
def recognize_page():
    return render_template("recognize.html")

@app.route("/users")
def users_page():
    users = []
    if os.path.exists(FACES_DB):
        with sqlite3.connect(FACES_DB) as conn:
            rows = conn.execute('''
                SELECT person_name, COUNT(*) as embedding_count, MAX(registered_at) as last_registered
                FROM user_embeddings
                GROUP BY person_name
                ORDER BY person_name ASC
            ''').fetchall()

        users = [
            {
                "folder":          row[0],
                "display":         row[0].replace("_", " "),
                "embeddings":      row[1],
                "last_registered": row[2] or "unknown",
            }
            for row in rows
        ]

    return render_template("users.html", users=users)
@app.route("/attendance")
def attendance_page():
    return render_template("attendance.html")


# ══════════════════════════════════════════════════════════════════════════════
#  API — REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/register/start", methods=["POST"])
def api_register_start():
    data = request.get_json()
    name = data.get("name", "").strip().replace(" ", "_")
    if not name:
        return jsonify({"error": "Name is required"}), 400

    person_dir = os.path.join(FACES_DIR, name)
    os.makedirs(person_dir, exist_ok=True)

    sid = f"{name}_{int(time.time())}"
    reg_sessions[sid] = {
        "name":                name,
        "dir":                 person_dir,
        "shots":               0,
        "max_shots":           5,
        "stability":           0,
        "stability_threshold": 12,
        "bursting":            False,
    }
    return jsonify({"session_id": sid, "name": name, "max_shots": 5})


@app.route("/api/register/frame", methods=["POST"])
def api_register_frame():
    data  = request.get_json()
    sid   = data.get("session_id")
    image = data.get("image")

    if not sid or sid not in reg_sessions:
        return jsonify({"error": "Invalid session"}), 400

    reg = reg_sessions[sid]

    if reg["shots"] >= reg["max_shots"]:
        return jsonify({
            "status":    "COMPLETE",
            "shots":     reg["shots"],
            "max_shots": reg["max_shots"],
            "progress":  1.0,
        })

    frame = decode_base64_image(image)
    if frame is None:
        return jsonify({"error": "Bad image"}), 400

    faces = detector.detect(frame)

    if not faces:
        reg["stability"] = 0
        reg["bursting"]  = False
        return jsonify({
            "status":    "NO_FACE",
            "reasons":   ["No face detected"],
            "shots":     reg["shots"],
            "max_shots": reg["max_shots"],
            "progress":  0,
        })

    face = faces[0]
    passed, reasons = detector.quality_check(frame, face)

    if not passed:
        reg["stability"] = 0
        reg["bursting"]  = False
        return jsonify({
            "status":    "INVALID",
            "reasons":   reasons,
            "shots":     reg["shots"],
            "max_shots": reg["max_shots"],
            "progress":  0,
        })

    crop_bgr = ArcFaceRecognizer.pad_to_square(detector.crop_face(frame, face))
    if reg["bursting"]:
        reg["shots"] += 1
        ts   = int(time.time() * 1000)
        path = os.path.join(reg["dir"], f"face_{reg['shots']}_{ts}.jpg")
        cv2.imwrite(path, crop_bgr)
        status   = "COMPLETE" if reg["shots"] >= reg["max_shots"] else "BURST_CAPTURE"
        progress = 1.0
    else:
        reg["stability"] += 1
        progress = min(reg["stability"] / reg["stability_threshold"], 1.0)

        if reg["stability"] >= reg["stability_threshold"]:
            reg["bursting"] = True
            reg["shots"] += 1
            ts   = int(time.time() * 1000)
            path = os.path.join(reg["dir"], f"face_{reg['shots']}_{ts}.jpg")
            cv2.imwrite(path, crop_bgr)
            status = "COMPLETE" if reg["shots"] >= reg["max_shots"] else "BURST_CAPTURE"
        else:
            status = "STABILIZING"

    return jsonify({
        "status":    status,
        "shots":     reg["shots"],
        "max_shots": reg["max_shots"],
        "progress":  progress,
    })


@app.route("/api/register/finish", methods=["POST"])
def api_register_finish():
    data = request.get_json()
    sid  = data.get("session_id")

    if not sid or sid not in reg_sessions:
        return jsonify({"error": "Invalid session"}), 400

    reg        = reg_sessions[sid]
    name       = reg["name"]
    person_dir = reg["dir"]

    # ── Build embeddings and store in local faces.db ──────────────────────────
    conn   = sqlite3.connect(FACES_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_embeddings (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            person_name   TEXT,
            embedding     BLOB,
            device_id     TEXT,
            registered_at TEXT DEFAULT CURRENT_TIMESTAMP,
            synced        INTEGER DEFAULT 0
        )
    """)
    conn.commit()

    images     = glob.glob(os.path.join(person_dir, "*.jpg"))
    embeddings = []
    for img_path in images:
        face = cv2.imread(img_path)
        if face is not None:
            emb = recognizer.get_embedding(face)
            embeddings.append(emb)

    saved      = 0
    chunk_size = 5
    for i in range(0, len(embeddings), chunk_size):
        chunk = embeddings[i: i + chunk_size]
        if chunk:
            avg = np.mean(np.array(chunk), axis=0).astype(np.float32)
            cursor.execute(
                """INSERT INTO user_embeddings
                       (person_name, embedding, device_id, synced)
                   VALUES (?, ?, ?, 0)""",
                (name, avg.tobytes(), "device_1_id"),  # synced=0 → will be pushed to host
            )
            saved += 1

    conn.commit()
    conn.close()

    # ── Delete raw images after embedding extraction ──────────────────────────
    #shutil.rmtree(person_dir)
    #print(f"Deleted raw images for '{name}' after embedding extraction.")

    # ── Reload recognizer ─────────────────────────────────────────────────────
    recognizer.load_database(DATA_DIR)

    # ── Trigger immediate face push to host ───────────────────────────────────
    if _syncer is not None:
        import threading
        threading.Thread(target=_syncer._push_new_embeddings, daemon=True).start()

    del reg_sessions[sid]
    return jsonify({"success": True, "name": name, "embeddings_saved": saved})


# ══════════════════════════════════════════════════════════════════════════════
#  API — RECOGNITION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/recognize/frame", methods=["POST"])
def api_recognize_frame():
    data  = request.get_json()
    image = data.get("image")

    frame = decode_base64_image(image)
    if frame is None:
        return jsonify({"error": "Bad image"}), 400

    faces = detector.detect(frame)

    if not faces:
        recog_state["tracking_name"]      = None
        recog_state["consecutive_matches"] = 0
        return jsonify({"status": "no_face", "name": None, "confidence": 0})

    face = faces[0]
    passed, reasons = detector.quality_check(frame, face)

    if not passed:
        recog_state["tracking_name"]      = None
        recog_state["consecutive_matches"] = 0
        return jsonify({
            "status":      "low_quality",
            "name":        None,
            "confidence":  0,
            "reasons":     reasons,
            "logged":      False,
            "consecutive": 0,
            "required":    recog_state["required_matches"],
        })

    crop_bgr = detector.crop_face(frame, face)

    name, confidence = recognizer.recognize(crop_bgr)

    logged = False
    now    = time.time()

    if name != "Unknown":
        if name == recog_state["tracking_name"]:
            recog_state["consecutive_matches"] += 1
        else:
            recog_state["tracking_name"]      = name
            recog_state["consecutive_matches"] = 1

        if recog_state["consecutive_matches"] >= recog_state["required_matches"]:
            last = recog_state["recently_logged"].get(name, 0)
            if now - last > recog_state["log_cooldown"]:
                recognizer.log_attendance(name)
                recog_state["recently_logged"][name] = now
                logged = True
    else:
        recog_state["tracking_name"]      = None
        recog_state["consecutive_matches"] = 0

    return jsonify({
        "status":      "recognized" if name != "Unknown" else "unknown",
        "name":        name,
        "confidence":  round(confidence, 4),
        "logged":      logged,
        "consecutive": recog_state["consecutive_matches"],
        "required":    recog_state["required_matches"],
    })


# ══════════════════════════════════════════════════════════════════════════════
#  API — USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/users/delete/<name>", methods=["POST"])
def api_delete_user(name):
    # 1. Remove from local faces.db
    if os.path.exists(FACES_DB):
        with sqlite3.connect(FACES_DB) as conn:
            conn.execute(
                "DELETE FROM user_embeddings WHERE person_name = ?", (name,)
            )
            conn.commit()
        print(f"Deleted local embeddings for '{name}'.")

    # 2. Remove raw image folder if it still exists
    user_dir = os.path.join(FACES_DIR, name)
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)

    # 3. Reload recognizer
    recognizer.load_database(DATA_DIR)

    # 4. Push deletion to host so all other devices sync it
    if _syncer is not None:
        import threading
        threading.Thread(
            target=_syncer.push_delete, args=(name,), daemon=True
        ).start()

    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════════════════════
#  API — ATTENDANCE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/attendance/today")
def api_attendance_today():
    if not os.path.exists(ATTENDANCE_DB):
        return jsonify({"records": [], "count": 0})

    with sqlite3.connect(ATTENDANCE_DB) as conn:
        today = datetime.now().strftime("%Y-%m-%d")
        rows  = conn.execute(
            "SELECT person_name, timestamp FROM attendance_logs "
            "WHERE timestamp LIKE ? ORDER BY timestamp DESC",
            (f"{today}%",),
        ).fetchall()

    records = [{"name": r[0], "timestamp": r[1]} for r in rows]
    return jsonify({"records": records, "count": len(records)})


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

from network_sync import AttendanceSyncer

if __name__ == "__main__":
    print("=" * 50)
    print("  Face Recognition Attendance System")
    print("  Open http://localhost:5000 in your browser")
    print("=" * 50)

    _syncer = AttendanceSyncer(
        db_path       = ATTENDANCE_DB,
        faces_db_path = FACES_DB,
        gateway_url   = "https://10.40.91.184:5100",  # ← all traffic through gateway
        sync_interval = 60.0,
        recognizer    = recognizer,
    )
    _syncer.start_syncing()

    try:
        app.run(host="127.0.0.1", port=5000, debug=False)
    finally:
        _syncer.stop_syncing()