from flask import Flask, request, jsonify, Response
import requests
import json
import time
import base64
import threading
import logging
import os
import zmq
import sqlite3

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import zeroconf_utils

app = Flask(__name__)

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s'
)

# ── Config ────────────────────────────────────────────────────────────────────
HOST_BASE_URL = os.environ.get("HOST_BASE_URL", "http://127.0.0.1:5050")
HOST_TOKEN    = os.environ.get("HOST_TOKEN",    "host_token_123")
USE_HTTPS     = False   # ← flip to True after generating gateway.crt / gateway.key

if not HOST_TOKEN:
    raise RuntimeError("HOST_TOKEN environment variable not set.")

# ── Routes the gateway will NOT forward (handled locally) ─────────────────────
LOCAL_ONLY_ROUTES = {"/health"}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Camera Tracker Status Polling ──────────────────────────────────────────
OCCUPANCY_DB = os.path.join(BASE_DIR, "occupancy.db")
CAMERA_STATUS_URL_FALLBACK = os.environ.get("CAMERA_STATUS_URL", "")

_camera_url_cache: str | None = None
_camera_failures = 0

def _resolve_camera_url() -> str:
    global _camera_url_cache
    if _camera_url_cache:
        return _camera_url_cache
    info = zeroconf_utils.discover_service("_camera-http._tcp", timeout=1.0)
    if info:
        _camera_url_cache = f"{zeroconf_utils.resolve_url(info, use_https=USE_HTTPS)}/status"
        return _camera_url_cache
    if CAMERA_STATUS_URL_FALLBACK:
        return CAMERA_STATUS_URL_FALLBACK
    return ""

GATEWAY_START_TIME: float | None = None
_camera_first_data_time: float | None = None
_camera_last_online: float = 0.0

# ── Public Key Registry ───────────────────────────────────────────────────────
PUBLIC_KEYS_DIR = os.path.join(BASE_DIR, "public_keys")
os.makedirs(PUBLIC_KEYS_DIR, exist_ok=True)

MAX_AGE = 30  # seconds

def load_public_keys() -> dict:
    keys = {}
    for filename in os.listdir(PUBLIC_KEYS_DIR):
        if not filename.endswith(".pem"):
            continue
        device_id = filename[:-4]
        filepath  = os.path.join(PUBLIC_KEYS_DIR, filename)
        try:
            with open(filepath, "rb") as f:
                keys[device_id] = serialization.load_pem_public_key(f.read())
            print(f"Loaded public key for device: '{device_id}'")
        except Exception as e:
            logging.error(f"Failed to load public key '{filename}': {e}")
    return keys

_public_keys = load_public_keys()

if not _public_keys:
    print("WARNING: No public keys loaded. No devices can authenticate.")


# ── Replay Window ─────────────────────────────────────────────────────────────
_replay_window = {}
_replay_lock   = threading.Lock()

def _start_daemon(name, target, interval):
    def loop():
        while True:
            target()
            time.sleep(interval)
    threading.Thread(target=loop, daemon=True, name=name).start()

def clean_replay_window():
    now = time.time()
    with _replay_lock:
        expired = [k for k, v in _replay_window.items() if v < now]
        for k in expired:
            del _replay_window[k]

_start_daemon("replay-cleaner", clean_replay_window, 30)

# ── ZMQ Push to Camera Tracker ────────────────────────────────────────────────
_zmq_context = zmq.Context()
_tracker_push = _zmq_context.socket(zmq.PUSH)
_tracker_push.bind("tcp://0.0.0.0:5557")

# ── Occupancy Database Setup ────────────────────────────────────────────
def setup_occupancy_db():
    with sqlite3.connect(OCCUPANCY_DB) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute('''
            CREATE TABLE IF NOT EXISTS occupancy_snapshots (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       REAL    NOT NULL,
                people_count    INTEGER NOT NULL,
                known_count     INTEGER NOT NULL,
                unknown_count   INTEGER NOT NULL,
                linked_names    TEXT    DEFAULT '[]',
                pending_names   TEXT    DEFAULT '[]',
                cpu_percent     REAL    DEFAULT 0.0,
                gpu_percent     REAL    DEFAULT 0.0
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_occupancy_ts
            ON occupancy_snapshots(timestamp)
        ''')
        for col in ("cpu_percent", "gpu_percent"):
            try:
                conn.execute(f"ALTER TABLE occupancy_snapshots ADD COLUMN {col} REAL DEFAULT 0.0")
            except sqlite3.OperationalError:
                pass
        conn.commit()


def _retention_cleanup():
    cutoff = time.time() - 86400
    with sqlite3.connect(OCCUPANCY_DB) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("DELETE FROM occupancy_snapshots WHERE timestamp < ?", (cutoff,))
        conn.commit()


def _poll_camera_status():
    global _camera_first_data_time, _camera_url_cache, _camera_failures, _camera_last_online
    camera_url = _resolve_camera_url()
    if not camera_url:
        return
    try:
        req_kwargs = {"timeout": 5}
        if USE_HTTPS:
            req_kwargs["verify"] = False
        resp = requests.get(camera_url, **req_kwargs)
        _camera_failures = 0
        data = resp.json()

        now = time.time()
        _camera_last_online = now

        people_count = int(data.get("total_tracked", 0))
        linked       = data.get("linked_targets", {})
        pending      = data.get("pending_targets", [])
        linked_in_frame = int(data.get("linked_in_frame", 0))
        linked_in_frame_names = data.get("linked_in_frame_names", [])
        cpu_percent = float(data.get("cpu_percent", 0))
        gpu_percent = float(data.get("gpu_percent", 0))
        known_count  = linked_in_frame
        unknown_count = max(0, people_count - known_count)

        if linked_in_frame > len(linked):
            logging.warning("linked_in_frame (%d) exceeds linked_targets count (%d)", linked_in_frame, len(linked))

        if _camera_first_data_time is None and people_count >= 0:
            _camera_first_data_time = now

        with sqlite3.connect(OCCUPANCY_DB) as conn:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute('''
                INSERT INTO occupancy_snapshots
                    (timestamp, people_count, known_count, unknown_count,
                     linked_names, pending_names, cpu_percent, gpu_percent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                now,
                people_count,
                known_count,
                unknown_count,
                json.dumps(linked_in_frame_names),
                json.dumps(pending),
                cpu_percent,
                gpu_percent,
            ))
            conn.commit()
    except requests.RequestException as exc:
        _camera_failures += 1
        if _camera_failures >= 3:
            _camera_url_cache = None
        logging.warning("Camera status poll failed (%d/3): %s", _camera_failures, exc)
    except Exception as exc:
        logging.error("Camera status poll unexpected error: %s", exc)


setup_occupancy_db()
_start_daemon("occupancy-cleanup", _retention_cleanup, 3600)
_start_daemon("camera-poller", _poll_camera_status, 2.0)

_zc_gateway_http = zeroconf_utils.advertise_service(
    "_gateway-http._tcp", "GatewayHTTP", 5100
)
_zc_gateway_zmq = zeroconf_utils.advertise_service(
    "_gateway-zmq._tcp", "GatewayZMQ", 5557
)
print(f"Zeroconf: advertising _gateway-http._tcp (port 5100) and _gateway-zmq._tcp (port 5557)")

# ── RSA Signature Verification ────────────────────────────────────────────────
def verify_request(req, raw_body: str) -> tuple:
    device_id = req.headers.get("X-Device-ID")
    timestamp = req.headers.get("X-Timestamp")
    signature = req.headers.get("X-Signature")

    if not all([device_id, timestamp, signature]):
        return None, "Missing authentication headers"

    try:
        age = abs(int(time.time()) - int(timestamp))
    except ValueError:
        return None, "Invalid timestamp"

    if age > MAX_AGE:
        return None, f"Request expired ({age}s old, max {MAX_AGE}s)"

    sig_key = f"{device_id}.{signature[:16]}"
    with _replay_lock:
        if sig_key in _replay_window:
            logging.warning(f"Replay attack from device '{device_id}'")
            return None, "Duplicate request"
        _replay_window[sig_key] = time.time() + MAX_AGE

    public_key = _public_keys.get(device_id)
    if not public_key:
        logging.warning(f"Unknown device: '{device_id}'")
        return None, "Unknown device"

    try:
        sig_bytes = base64.b64decode(signature)
        message   = f"{device_id}.{timestamp}.{raw_body}".encode()

        public_key.verify(
            sig_bytes,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return device_id, None

    except InvalidSignature:
        logging.warning(f"Invalid RSA signature from device '{device_id}'")
        return None, "Invalid signature"
    except Exception as e:
        logging.error(f"Signature verification error: {e}")
        return None, "Verification error"


# ── Forward to Host ───────────────────────────────────────────────────────────
def forward_to_host(device_id: str, path: str, method: str, raw_body: bytes, content_type: str):
    target_url = f"{HOST_BASE_URL}{path}"

    forward_headers = {
        "Content-Type":  content_type or "application/json",
        "X-Sync-Token":  HOST_TOKEN,
        "X-Device-ID":   device_id,
    }

    try:
        host_response = requests.request(
            method=method,
            url=target_url,
            data=raw_body,
            headers=forward_headers,
            timeout=10,
        )

        return Response(
            response=host_response.content,
            status=host_response.status_code,
            content_type=host_response.headers.get("Content-Type", "application/json"),
        )

    except requests.RequestException as e:
        logging.error(f"Failed to reach host at {target_url}: {e}")
        return jsonify({"error": f"Could not reach host: {e}"}), 502


# ══════════════════════════════════════════════════════════════════════════════
#  LOCAL ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":             "ok",
        "registered_devices": list(_public_keys.keys()),
    }), 200


@app.route("/camera/track", methods=["POST"])
def camera_track():
    raw_body = request.get_data(as_text=True)
    device_id, error = verify_request(request, raw_body)
    if error:
        return jsonify({"error": error}), 401

    data = request.get_json()
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400

    _tracker_push.send_json({
        "action": "track",
        "name": name,
        "device_id": device_id,
        "timestamp": time.time(),
    })
    return jsonify({"status": "ok", "name": name}), 200


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/dashboard/data", methods=["GET"])
def dashboard_data():
    cutoff = time.time() - 3600
    with sqlite3.connect(OCCUPANCY_DB) as conn:
        rows = conn.execute('''
            SELECT timestamp, people_count, known_count, unknown_count,
                   linked_names, pending_names, cpu_percent, gpu_percent
            FROM occupancy_snapshots
            WHERE timestamp > ?
            ORDER BY timestamp ASC
        ''', (cutoff,)).fetchall()

    current = rows[-1] if rows else None
    gateway_uptime  = int(time.time() - GATEWAY_START_TIME) if GATEWAY_START_TIME else 0
    now = time.time()
    camera_online = (now - _camera_last_online) < 10
    camera_uptime = int(now - _camera_first_data_time) if (_camera_first_data_time and camera_online) else 0

    return jsonify({
        "current": {
            "count":    current[1] if current else 0,
            "known":    current[2] if current else 0,
            "unknown":  current[3] if current else 0,
            "linked":   json.loads(current[4]) if current else [],
            "pending":  json.loads(current[5]) if current else [],
            "cpu":      current[6] if current else 0,
            "gpu":      current[7] if current else 0,
            "time":     current[0] if current else 0,
        },
        "uptime": {
            "gateway": gateway_uptime,
            "camera":  camera_uptime,
        },
        "history": [
            {
                "t":       row[0],
                "count":   row[1],
                "known":   row[2],
                "unknown": row[3],
            }
            for row in rows
        ],
    })


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Room Occupancy</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
  <style>
    :root {
      --bg-base:        #0f1117;
      --bg-surface:     #161b25;
      --bg-elevated:    #1e2535;
      --border-subtle:  rgba(255,255,255,0.06);
      --border-default: rgba(255,255,255,0.10);
      --text-primary:   #e8eaf0;
      --text-secondary: #8b91a5;
      --text-tertiary:  #555d72;
      --green:          #34c97e;
      --green-bg:       rgba(52,201,126,0.10);
      --green-border:   rgba(52,201,126,0.25);
      --amber:          #f5a623;
      --amber-bg:       rgba(245,166,35,0.10);
      --amber-border:   rgba(245,166,35,0.25);
      --red:            #e05252;
      --red-bg:         rgba(224,82,82,0.10);
      --red-border:     rgba(224,82,82,0.25);
      --blue:           #4d91e6;
      --font-sans:      'DM Sans', sans-serif;
      --font-mono:      'JetBrains Mono', monospace;
      --radius-md:  8px;
      --radius-lg:  12px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body {
      font-family: var(--font-sans);
      background: var(--bg-base);
      color: var(--text-primary);
      height: 100vh;
      overflow: hidden;
      padding: 14px 18px;
      font-size: 13px;
      line-height: 1.4;
      display: flex;
      flex-direction: column;
    }

    /* ── Full-height dashboard grid ── */
    .dashboard {
      flex: 1;
      display: grid;
      grid-template-rows: auto auto 1fr auto;
      gap: 10px;
      min-height: 0;
    }

    /* Header */
    .header { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    .header-left { display: flex; align-items: baseline; gap: 14px; }
    .header-title { font-size: 17px; font-weight: 600; color: var(--text-primary); letter-spacing: -0.02em; }
    .header-subtitle { font-size: 11px; color: var(--text-tertiary); font-family: var(--font-mono); }

    /* Badge */
    .badge {
      display: inline-flex; align-items: center; gap: 5px;
      font-size: 11px; font-weight: 500; padding: 4px 10px;
      border-radius: 99px; white-space: nowrap; border: 1px solid;
    }
    .badge-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }
    .badge-empty   { background: var(--amber-bg);  color: var(--amber); border-color: var(--amber-border); }
    .badge-active  { background: var(--green-bg);  color: var(--green); border-color: var(--green-border); }
    .badge-known   { background: var(--green-bg);  color: var(--green); border-color: var(--green-border); }
    .badge-unknown { background: var(--red-bg);    color: var(--red);   border-color: var(--red-border);   }
    .badge-pending { background: var(--amber-bg);  color: var(--amber); border-color: var(--amber-border); }
    .badge-online  { background: var(--green-bg);  color: var(--green); border-color: var(--green-border); }
    .badge-offline { background: var(--red-bg);    color: var(--red);   border-color: var(--red-border);   }

    /* Persons bar */
    .persons-bar {
      background: var(--bg-surface); border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg); padding: 9px 16px;
      display: flex; align-items: center; gap: 10px;
    }
    .persons-label { font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-tertiary); white-space: nowrap; }
    .persons-tags  { display: flex; flex-wrap: wrap; gap: 6px; }

    /* Metrics + chart + panels — main content row */
    .main-row {
      display: grid;
      grid-template-columns: 220px 1fr 200px;
      gap: 10px;
      min-height: 0;
    }

    /* Left column: metric cards stacked */
    .metrics-col {
      display: flex; flex-direction: column; gap: 10px;
    }
    .metric-card {
      background: var(--bg-surface); border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg); padding: 14px 16px;
      display: flex; flex-direction: column; gap: 6px;
      flex: 1;
      transition: border-color 0.2s;
    }
    .metric-card:hover { border-color: var(--border-default); }
    .metric-label {
      font-size: 10px; font-weight: 500; text-transform: uppercase;
      letter-spacing: 0.07em; color: var(--text-tertiary);
      display: flex; align-items: center; gap: 6px;
    }
    .metric-value { font-size: 32px; font-weight: 600; letter-spacing: -0.03em; line-height: 1; }
    .metric-sub   { font-size: 11px; color: var(--text-tertiary); font-family: var(--font-mono); }
    .v-default { color: var(--text-primary); }
    .v-green   { color: var(--green); }
    .v-red     { color: var(--red); }

    /* Centre: chart */
    .chart-card {
      background: var(--bg-surface); border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg); padding: 16px 18px;
      display: flex; flex-direction: column; min-height: 0;
    }
    .chart-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; flex-shrink: 0; }
    .chart-title  { font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-tertiary); }
    .legend       { display: flex; gap: 14px; }
    .legend-item  { display: flex; align-items: center; gap: 5px; font-size: 11px; color: var(--text-secondary); }
    .legend-swatch{ width: 16px; height: 3px; border-radius: 2px; }
    .chart-wrap   { position: relative; flex: 1; min-height: 0; }
    .chart-wrap canvas { position: absolute; inset: 0; width: 100% !important; height: 100% !important; }

    /* Right column: connection + system stacked */
    .right-col { display: flex; flex-direction: column; gap: 10px; }
    .panel {
      background: var(--bg-surface); border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg); padding: 14px 16px;
      flex: 1;
    }
    .panel-title {
      font-size: 10px; font-weight: 500; text-transform: uppercase;
      letter-spacing: 0.07em; color: var(--text-tertiary);
      margin-bottom: 12px; display: flex; align-items: center; gap: 6px;
    }

    /* Status rows */
    .status-row { display: flex; align-items: center; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border-subtle); }
    .status-row:last-of-type { border-bottom: none; }
    .status-key { display: flex; align-items: center; gap: 7px; color: var(--text-secondary); font-size: 12px; }
    .status-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
    .dot-online  { background: var(--green); box-shadow: 0 0 5px var(--green); }
    .dot-offline { background: var(--red);   box-shadow: 0 0 5px var(--red); }
    .uptime-note { margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border-subtle); font-size: 11px; color: var(--text-tertiary); font-family: var(--font-mono); }

    /* System bars */
    .sys-row { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--border-subtle); }
    .sys-row:last-of-type { border-bottom: none; }
    .sys-label { font-size: 11px; color: var(--text-secondary); width: 30px; font-family: var(--font-mono); }
    .sys-bar   { flex: 1; height: 4px; background: var(--bg-elevated); border-radius: 3px; overflow: hidden; }
    .sys-fill  { height: 100%; border-radius: 3px; transition: width 0.6s ease; }
    .sys-pct   { font-size: 11px; font-weight: 500; font-family: var(--font-mono); color: var(--text-secondary); width: 30px; text-align: right; }
  </style>
</head>
<body>
<div class="dashboard">

  <!-- Row 1: Header -->
  <div class="header">
    <div class="header-left">
      <div class="header-title">Room Occupancy</div>
      <div class="header-subtitle">Live · polling /status every 2s · auto-refreshes every 2s</div>
    </div>
    <span class="badge badge-empty" id="header-badge">
      <span class="badge-dot" style="background:var(--amber)"></span>No one in view
    </span>
  </div>

  <!-- Row 2: Persons bar -->
  <div class="persons-bar">
    <span class="persons-label">Currently tracked</span>
    <div class="persons-tags" id="persons-tags">
      <span class="badge badge-empty">
        <span class="badge-dot" style="background:var(--amber)"></span>No one in view
      </span>
    </div>
  </div>

  <!-- Row 3: Main content (metrics | chart | right panels) -->
  <div class="main-row">

    <!-- Left: metric cards -->
    <div class="metrics-col">
      <div class="metric-card">
        <div class="metric-label">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
          People in room
        </div>
        <div class="metric-value v-default" id="people-count">—</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><polyline points="16 11 18 13 22 9"/></svg>
          Known
        </div>
        <div class="metric-value v-green" id="known-count">—</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/><line x1="12" y1="17" x2="12" y2="21"/><circle cx="12" cy="13" r="0.5" fill="currentColor"/></svg>
          Unknown
        </div>
        <div class="metric-value v-red" id="unknown-count">—</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          Uptime
        </div>
        <div class="metric-value v-default" id="uptime-value" style="font-size:22px">—</div>
        <div class="metric-sub">Gateway</div>
      </div>
    </div>

    <!-- Centre: chart (fills remaining space) -->
    <div class="chart-card">
      <div class="chart-header">
        <span class="chart-title">Occupancy over time (last 1 hour)</span>
        <div class="legend">
          <span class="legend-item"><span class="legend-swatch" style="background:#34c97e"></span>Known</span>
          <span class="legend-item"><span class="legend-swatch" style="background:#e05252"></span>Unknown</span>
          <span class="legend-item"><span class="legend-swatch" style="background:rgba(77,145,230,0.7)"></span>Total</span>
        </div>
      </div>
      <div class="chart-wrap">
        <canvas id="occChart" role="img" aria-label="Line chart of room occupancy over the last hour">No data yet.</canvas>
      </div>
    </div>

    <!-- Right: connection + system -->
    <div class="right-col">
      <div class="panel">
        <div class="panel-title">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
          Connection
        </div>
        <div class="status-row">
          <span class="status-key"><span class="status-dot dot-online" id="gw-dot"></span>Gateway</span>
          <span class="badge badge-online" id="gw-badge">Online</span>
        </div>
        <div class="status-row">
          <span class="status-key"><span class="status-dot" id="cam-dot"></span>Camera</span>
          <span class="badge" id="cam-badge">—</span>
        </div>
        <div class="uptime-note" id="uptime-note">Gateway uptime: —</div>
      </div>

      <div class="panel">
        <div class="panel-title">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
          System
        </div>
        <div class="sys-row">
          <span class="sys-label">CPU</span>
          <div class="sys-bar"><div class="sys-fill" id="cpu-bar" style="width:0%;background:var(--green)"></div></div>
          <span class="sys-pct" id="cpu-pct">—</span>
        </div>
        <div class="sys-row">
          <span class="sys-label">GPU</span>
          <div class="sys-bar"><div class="sys-fill" id="gpu-bar" style="width:0%;background:var(--green)"></div></div>
          <span class="sys-pct" id="gpu-pct">—</span>
        </div>
      </div>
    </div>

  </div>

</div>

<script>
  let occChart = null;
  let lastChartUpdate = 0;

  function fmtTime(ts) {
    const d = new Date(ts * 1000);
    return String(d.getHours()).padStart(2,'0') + ':' +
           String(d.getMinutes()).padStart(2,'0') + ':' +
           String(d.getSeconds()).padStart(2,'0');
  }

  function fmtUptime(secs) {
    if (!secs || secs <= 0) return 'offline';
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    const parts = [];
    if (h > 0) parts.push(h + 'h');
    if (m > 0 || h > 0) parts.push(m + 'm');
    parts.push(s + 's');
    return parts.join(' ');
  }

  function barColor(v) {
    if (v > 80) return 'var(--red)';
    if (v > 50) return 'var(--amber)';
    return 'var(--green)';
  }

  function updatePersonsTags(linked, pending, unknownCount) {
    const container = document.getElementById('persons-tags');
    const headerBadge = document.getElementById('header-badge');
    container.innerHTML = '';

    const total = linked.length + unknownCount;
    if (total === 0 && pending.length === 0) {
      container.innerHTML = '<span class="badge badge-empty"><span class="badge-dot" style="background:var(--amber)"></span>No one in view</span>';
      headerBadge.className = 'badge badge-empty';
      headerBadge.innerHTML = '<span class="badge-dot" style="background:var(--amber)"></span>No one in view';
      return;
    }

    headerBadge.className = 'badge badge-active';
    headerBadge.innerHTML = '<span class="badge-dot" style="background:var(--green)"></span>' + total + ' in room';

    linked.forEach(name => {
      const el = document.createElement('span');
      el.className = 'badge badge-known';
      el.innerHTML = '<span class="badge-dot" style="background:var(--green)"></span>' + name;
      container.appendChild(el);
    });
    if (unknownCount > 0) {
      const el = document.createElement('span');
      el.className = 'badge badge-unknown';
      el.innerHTML = '<span class="badge-dot" style="background:var(--red)"></span>' + unknownCount + ' unknown';
      container.appendChild(el);
    }
    pending.forEach(name => {
      const el = document.createElement('span');
      el.className = 'badge badge-pending';
      el.innerHTML = '<span class="badge-dot" style="background:var(--amber)"></span>' + name + ' (pending)';
      container.appendChild(el);
    });
  }

  function setCameraStatus(isOnline, camUptime) {
    const dot   = document.getElementById('cam-dot');
    const badge = document.getElementById('cam-badge');
    if (isOnline) {
      dot.className   = 'status-dot dot-online';
      badge.className = 'badge badge-online';
      badge.textContent = 'Online';
    } else {
      dot.className   = 'status-dot dot-offline';
      badge.className = 'badge badge-offline';
      badge.textContent = 'Offline';
    }
  }

  function initChart(labels, totalData, knownData, unknownData) {
    const ctx = document.getElementById('occChart').getContext('2d');
    occChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Total',
            data: totalData,
            borderColor: 'rgba(77,145,230,0.7)',
            backgroundColor: 'rgba(77,145,230,0.05)',
            borderWidth: 1.5,
            borderDash: [5, 4],
            fill: true, tension: 0, pointRadius: 0
          },
          {
            label: 'Known',
            data: knownData,
            borderColor: '#34c97e',
            backgroundColor: 'rgba(52,201,126,0.10)',
            borderWidth: 1.5,
            fill: true, tension: 0, pointRadius: 0
          },
          {
            label: 'Unknown',
            data: unknownData,
            borderColor: '#e05252',
            backgroundColor: 'rgba(224,82,82,0.08)',
            borderWidth: 1.5,
            fill: true, tension: 0, pointRadius: 0
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 0 },
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#1e2535',
            titleColor: '#8b91a5',
            bodyColor: '#e8eaf0',
            borderColor: 'rgba(255,255,255,0.10)',
            borderWidth: 1,
            padding: 10,
            cornerRadius: 8,
            callbacks: { label: ctx => ' ' + ctx.dataset.label + ': ' + ctx.parsed.y }
          }
        },
        scales: {
          x: {
            display: true,
            ticks: { color: '#555d72', font: { size: 10, family: "'JetBrains Mono', monospace" }, maxTicksLimit: 8, maxRotation: 0 },
            grid:  { display: false },
            border:{ display: false }
          },
          y: {
            min: 0,
            ticks: { stepSize: 1, color: '#555d72', font: { size: 11, family: "'JetBrains Mono', monospace" } },
            grid:  { color: 'rgba(255,255,255,0.04)' },
            border:{ display: false }
          }
        }
      }
    });
  }

  function fetchData() {
    fetch('/dashboard/data')
      .then(r => r.json())
      .then(d => {
        const c = d.current;

        // Metrics
        document.getElementById('people-count').textContent  = c.count;
        document.getElementById('known-count').textContent   = c.known;
        document.getElementById('unknown-count').textContent = c.unknown;
        document.getElementById('uptime-value').textContent  = fmtUptime(d.uptime.gateway);

        // People count color
        const pcEl = document.getElementById('people-count');
        pcEl.className = 'metric-value ' + (c.count > 0 ? 'v-green' : 'v-default');

        // Persons bar
        updatePersonsTags(c.linked, c.pending, c.unknown);

        // Camera status
        const camOnline = d.uptime.camera > 0;
        setCameraStatus(camOnline, d.uptime.camera);
        document.getElementById('uptime-note').textContent = 'Gateway uptime: ' + fmtUptime(d.uptime.gateway);

        // System bars
        const cpu = Math.round(c.cpu);
        const gpu = Math.round(c.gpu);
        document.getElementById('cpu-bar').style.width      = cpu + '%';
        document.getElementById('cpu-bar').style.background = barColor(cpu);
        document.getElementById('cpu-pct').textContent      = cpu + '%';
        document.getElementById('gpu-bar').style.width      = gpu + '%';
        document.getElementById('gpu-bar').style.background = barColor(gpu);
        document.getElementById('gpu-pct').textContent      = gpu + '%';

        // Chart — update every 30s to avoid overhead
        const now = Date.now();
        if (now - lastChartUpdate >= 30000 || !occChart) {
          lastChartUpdate = now;
          const labels      = d.history.map(h => fmtTime(h.t));
          const totalData   = d.history.map(h => h.count);
          const knownData   = d.history.map(h => h.known);
          const unknownData = d.history.map(h => h.unknown);
          if (!occChart) {
            initChart(labels, totalData, knownData, unknownData);
          } else {
            occChart.data.labels            = labels;
            occChart.data.datasets[0].data  = totalData;
            occChart.data.datasets[1].data  = knownData;
            occChart.data.datasets[2].data  = unknownData;
            occChart.update('none');
          }
        }
      })
      .catch(() => {});
  }

  fetchData();
  setInterval(fetchData, 2000);
</script>
</body>
</html>"""


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return DASHBOARD_HTML, 200, {"Content-Type": "text/html"}


# ══════════════════════════════════════════════════════════════════════════════
#  CATCH-ALL PROXY
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path):
    full_path = f"/{path}"
    raw_body = request.get_data(as_text=True)

    device_id, error = verify_request(request, raw_body)
    if error:
        return jsonify({"error": error}), 401

    return forward_to_host(
        device_id    = device_id,
        path         = full_path,
        method       = request.method,
        raw_body     = request.get_data(),
        content_type = request.content_type,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    GATEWAY_START_TIME = time.time()
    if USE_HTTPS:
        cert_file = "gateway.crt"
        key_file  = "gateway.key"
        if os.path.exists(cert_file) and os.path.exists(key_file):
            print("HTTPS enabled.")
            ssl_context = (cert_file, key_file)
        else:
            print("ERROR: USE_HTTPS=True but cert files not found. Run generate_cert.bat.")
            exit(1)
    else:
        print("WARNING: Running plain HTTP — for testing only.")
        ssl_context = None

    app.run(
        host="0.0.0.0",
        port=5100,
        ssl_context=ssl_context,
        debug=False
    )
