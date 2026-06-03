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

GATEWAY_START_TIME = time.time()
_camera_first_data_time: float | None = None

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
    global _camera_first_data_time, _camera_url_cache, _camera_failures
    camera_url = _resolve_camera_url()
    if not camera_url:
        _camera_first_data_time = None
        return
    try:
        req_kwargs = {"timeout": 5}
        if USE_HTTPS:
            req_kwargs["verify"] = False
        resp = requests.get(camera_url, **req_kwargs)
        _camera_failures = 0
        data = resp.json()

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
            _camera_first_data_time = time.time()

        with sqlite3.connect(OCCUPANCY_DB) as conn:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute('''
                INSERT INTO occupancy_snapshots
                    (timestamp, people_count, known_count, unknown_count,
                     linked_names, pending_names, cpu_percent, gpu_percent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
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
        _camera_first_data_time = None
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
    """
    Verify RSA-PSS signature on any incoming request.
    Uses raw_body string to avoid JSON re-serialization mismatch.
    Returns (device_id, None) on success or (None, error_string) on failure.
    """
    device_id = req.headers.get("X-Device-ID")
    timestamp = req.headers.get("X-Timestamp")
    signature = req.headers.get("X-Signature")

    # 1. All auth headers must be present
    if not all([device_id, timestamp, signature]):
        return None, "Missing authentication headers"

    # 2. Timestamp freshness
    try:
        age = abs(int(time.time()) - int(timestamp))
    except ValueError:
        return None, "Invalid timestamp"

    if age > MAX_AGE:
        return None, f"Request expired ({age}s old, max {MAX_AGE}s)"

    # 3. Replay check
    sig_key = f"{device_id}.{signature[:16]}"
    with _replay_lock:
        if sig_key in _replay_window:
            logging.warning(f"Replay attack from device '{device_id}'")
            return None, "Duplicate request"
        _replay_window[sig_key] = time.time() + MAX_AGE

    # 4. Device must have a registered public key
    public_key = _public_keys.get(device_id)
    if not public_key:
        logging.warning(f"Unknown device: '{device_id}'")
        return None, "Unknown device"

    # 5. Verify RSA-PSS signature against raw body
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
    """
    Forward a verified request to the host, stripping RSA headers
    and injecting HOST_TOKEN + device_id.
    Returns a Flask Response mirroring the host's response.
    """
    target_url = f"{HOST_BASE_URL}{path}"

    # Build clean headers for host — no RSA headers, just token
    forward_headers = {
        "Content-Type":  content_type or "application/json",
        "X-Sync-Token":  HOST_TOKEN,
        "X-Device-ID":   device_id,   # let host know which device this came from
    }

    try:
        host_response = requests.request(
            method=method,
            url=target_url,
            data=raw_body,             # forward exact raw body bytes
            headers=forward_headers,
            timeout=10,
        )

        # Mirror host response back to edge device
        return Response(
            response=host_response.content,
            status=host_response.status_code,
            content_type=host_response.headers.get("Content-Type", "application/json"),
        )

    except requests.RequestException as e:
        logging.error(f"Failed to reach host at {target_url}: {e}")
        return jsonify({"error": f"Could not reach host: {e}"}), 502


# ══════════════════════════════════════════════════════════════════════════════
#  LOCAL ROUTES  (handled by gateway, not forwarded)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    """Gateway health check — not forwarded to host."""
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
    gateway_uptime  = int(time.time() - GATEWAY_START_TIME)
    camera_uptime   = int(time.time() - _camera_first_data_time) if _camera_first_data_time else 0

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


DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Room Occupancy Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0d1117; color: #c9d1d9;
            min-height: 100vh; padding: 30px;
        }
        h1 { font-size: 28px; margin-bottom: 4px; color: #e6edf3; }
        .subtitle { color: #8b949e; font-size: 14px; margin-bottom: 24px; }
        .dashboard-layout { display: flex; gap: 16px; align-items: flex-start; }
        .left-col { flex: 3; display: flex; flex-direction: column; gap: 16px; min-width: 0; }
        .right-col { flex: 1; display: flex; flex-direction: column; gap: 12px; min-width: 200px; }
        .card {
            background: #161b22; border: 1px solid #30363d; border-radius: 12px;
            padding: 20px;
        }
        .card-label { font-size: 13px; color: #8b949e; text-transform: uppercase;
                       letter-spacing: 0.8px; margin-bottom: 8px; }
        .card-value { font-size: 42px; font-weight: 700; color: #e6edf3; }
        .card-small { font-size: 13px; color: #8b949e; margin-top: 4px; }
        .tracked-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
        .tracked-tag {
            background: #1f6feb33; border: 1px solid #1f6feb66;
            border-radius: 20px; padding: 4px 14px; font-size: 14px; color: #58a6ff;
        }
        .tracked-tag.unknown-tag {
            background: #f8514933; border-color: #f8514966; color: #f85149;
        }
        .tracked-tag.pending {
            background: #d2992233; border-color: #d2992266; color: #d29922;
        }
        .section-card {
            background: #161b22; border: 1px solid #30363d; border-radius: 12px;
            padding: 20px;
        }
        .section-label { font-size: 13px; color: #8b949e; text-transform: uppercase;
                          letter-spacing: 0.8px; margin-bottom: 8px; }
        .chart-card { display: flex; flex-direction: column; height: 350px; }
        .chart-card .section-label { flex-shrink: 0; }
        .chart-card canvas { width: 100%; flex: 1; }
        .uptime-block { display: flex; flex-direction: column; gap: 4px; }
        .uptime-row { display: flex; justify-content: space-between; align-items: baseline; }
        .uptime-row:not(:last-child) { padding-bottom: 6px; border-bottom: 1px solid #21262d; margin-bottom: 6px; }
        .uptime-label { font-size: 16px; color: #8b949e; }
        .uptime-value { font-size: 22px; font-weight: 600; color: #e6edf3; }
        .divider { border-top: 1px solid #21262d; margin: 8px 0; }
    </style>
</head>
<body>
    <h1>Room Occupancy</h1>
    <p class="subtitle">Live from camera tracker (polling /status every 2s) · Auto-refreshes every 2s</p>

    <div class="dashboard-layout">
        <div class="left-col">
            <div class="section-card">
                <div class="section-label">Currently Tracked Persons</div>
                <div id="tracked-list" class="tracked-list"></div>
            </div>
            <div class="section-card chart-card">
                <div class="section-label">Occupancy Over Time (last 1 hour)</div>
                <canvas id="chart-container"></canvas>
            </div>
        </div>
        <div class="right-col">
            <div class="card">
                <div class="card-label">People in Room</div>
                <div id="current-count" class="card-value">--</div>
            </div>
            <div class="card">
                <div class="card-label">Known</div>
                <div id="known-count" class="card-value" style="color:#3fb950">--</div>
            </div>
            <div class="card">
                <div class="card-label">Unknown</div>
                <div id="unknown-count" class="card-value" style="color:#f85149">--</div>
            </div>
            <div class="card">
                <div class="card-label">Uptime</div>
                <div id="uptime-gateway" class="uptime-value">--</div>
                <div class="card-small">Gateway</div>
                <div class="divider"></div>
                <div id="uptime-camera" class="uptime-value">--</div>
                <div class="card-small">Camera</div>
            </div>
            <div class="card">
                <div class="card-label">System</div>
                <div class="uptime-block">
                    <div class="uptime-row">
                        <span class="uptime-val" id="cpu-val">--</span>
                        <span class="uptime-lbl">CPU</span>
                    </div>
                    <div class="uptime-row">
                        <span class="uptime-val" id="gpu-val">--</span>
                        <span class="uptime-lbl">GPU</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let chart = null;
        let lastChartUpdate = 0;

        function fmtTime(ts) {
            const d = new Date(ts * 1000);
            return String(d.getHours()).padStart(2,'0') + ':' +
                   String(d.getMinutes()).padStart(2,'0') + ':' +
                   String(d.getSeconds()).padStart(2,'0');
        }

        function fmtUptime(secs) {
            if (secs === 0) return 'offline';
            const h = Math.floor(secs / 3600);
            const m = Math.floor((secs % 3600) / 60);
            const s = secs % 60;
            const parts = [];
            if (h > 0) parts.push(h + 'h');
            if (m > 0 || h > 0) parts.push(m + 'm');
            parts.push(s + 's');
            return parts.join(' ');
        }

        function fetchData() {
            fetch('/dashboard/data')
                .then(r => r.json())
                .then(d => {
                    document.getElementById('current-count').textContent = d.current.count;
                    document.getElementById('known-count').textContent = d.current.known;
                    document.getElementById('unknown-count').textContent = d.current.unknown;
                    document.getElementById('uptime-gateway').textContent = fmtUptime(d.uptime.gateway);
                    document.getElementById('uptime-camera').textContent = fmtUptime(d.uptime.camera);
                    document.getElementById('cpu-val').textContent = Math.round(d.current.cpu) + '%';
                    document.getElementById('gpu-val').textContent = Math.round(d.current.gpu) + '%';

                    const list = document.getElementById('tracked-list');
                    list.innerHTML = '';

                    if (d.current.linked.length === 0 && d.current.unknown === 0) {
                        const tag = document.createElement('span');
                        tag.className = 'tracked-tag pending';
                        tag.textContent = 'No one in view';
                        list.appendChild(tag);
                    } else {
                        d.current.linked.forEach(name => {
                            const tag = document.createElement('span');
                            tag.className = 'tracked-tag';
                            tag.textContent = name;
                            list.appendChild(tag);
                        });
                        if (d.current.unknown > 0) {
                            const tag = document.createElement('span');
                            tag.className = 'tracked-tag unknown-tag';
                            tag.textContent = d.current.unknown + ' unknown';
                            list.appendChild(tag);
                        }
                    }

                    d.current.pending.forEach(name => {
                        const tag = document.createElement('span');
                        tag.className = 'tracked-tag pending';
                        tag.textContent = name + ' (pending)';
                        list.appendChild(tag);
                    });

                    const now = Date.now();
                    if (now - lastChartUpdate >= 30000) {
                        lastChartUpdate = now;
                        const labels = d.history.map(h => fmtTime(h.t));
                        const totalData = d.history.map(h => h.count);
                        const knownData = d.history.map(h => h.known);
                        const unknownData = d.history.map(h => h.unknown);

                        if (chart) {
                            chart.data.labels = labels;
                            chart.data.datasets[0].data = totalData;
                            chart.data.datasets[1].data = knownData;
                            chart.data.datasets[2].data = unknownData;
                            chart.update('none');
                        } else {
                            const ctx = document.getElementById('chart-container').getContext('2d');
                            chart = new Chart(ctx, {
                                type: 'line',
                            data: {
                                labels: labels,
                                datasets: [
                                    {
                                        label: 'Total',
                                        data: totalData,
                                        borderColor: '#58a6ff',
                                        backgroundColor: '#1f6feb33',
                                        borderWidth: 2, fill: true, tension: 0.3,
                                        pointRadius: 1, pointHoverRadius: 5,
                                    },
                                    {
                                        label: 'Known',
                                        data: knownData,
                                        borderColor: '#3fb950',
                                        backgroundColor: '#3fb95022',
                                        borderWidth: 2, fill: true, tension: 0.3,
                                        pointRadius: 1, pointHoverRadius: 5,
                                    },
                                    {
                                        label: 'Unknown',
                                        data: unknownData,
                                        borderColor: '#f85149',
                                        backgroundColor: '#f8514922',
                                        borderWidth: 2, fill: true, tension: 0.3,
                                        pointRadius: 1, pointHoverRadius: 5,
                                    },
                                ]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    x: { ticks: { color: '#8b949e', maxTicksLimit: 16 }, grid: { color: '#21262d' } },
                                    y: { beginAtZero: true, ticks: { color: '#8b949e', stepSize: 1 },
                                         stacked: false, grid: { color: '#21262d' } }
                                },
                                plugins: { legend: { labels: { color: '#c9d1d9' } } }
                            }
                        });
                    }
                    }
                })
                .catch(() => {});
        }

        fetchData();
        setInterval(fetchData, 2000);
    </script>
</body>
</html>
"""


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return DASHBOARD_HTML, 200, {"Content-Type": "text/html"}


# ══════════════════════════════════════════════════════════════════════════════
#  CATCH-ALL PROXY  (verify RSA → forward everything else to host)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path):
    """
    Single catch-all route.
    Any request that passes RSA verification is forwarded to the host.

    Flow:
      1. Read raw body (used for signature verification)
      2. Verify RSA signature
      3. Forward to host with HOST_TOKEN
      4. Mirror host response back to client

    Adding new host endpoints requires NO changes to gateway.py —
    just add the route to host.py and the gateway forwards it automatically.
    """
    full_path = f"/{path}"

    # ── GET requests: no body to verify, use path + timestamp + empty string ──
    raw_body = request.get_data(as_text=True)  # empty string for GET

    # ── Verify RSA signature ──────────────────────────────────────────────────
    device_id, error = verify_request(request, raw_body)
    if error:
        return jsonify({"error": error}), 401

    # ── Forward to host ───────────────────────────────────────────────────────
    return forward_to_host(
        device_id    = device_id,
        path         = full_path,
        method       = request.method,
        raw_body     = request.get_data(),          # raw bytes for forwarding
        content_type = request.content_type,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
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
        host="0.0.0.0",   # bind all interfaces — zeroconf discovers IP automatically
        port=5100,
        ssl_context=ssl_context,
        debug=False
    )