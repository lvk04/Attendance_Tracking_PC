from flask import Flask, request, jsonify, Response
import requests
import json
import time
import base64
import threading
import logging
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s'
)

# ── Config ────────────────────────────────────────────────────────────────────
HOST_BASE_URL = os.environ.get("HOST_BASE_URL", "http://127.0.0.1:5050")
HOST_TOKEN    = os.environ.get("HOST_TOKEN",    "host_token_123")
USE_HTTPS     = True   # ← flip to True after generating gateway.crt / gateway.key

if not HOST_TOKEN:
    raise RuntimeError("HOST_TOKEN environment variable not set.")

# ── Routes the gateway will NOT forward (handled locally) ─────────────────────
LOCAL_ONLY_ROUTES = {"/health"}

# ── Public Key Registry ───────────────────────────────────────────────────────
PUBLIC_KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public_keys")
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

def clean_replay_window():
    now = time.time()
    with _replay_lock:
        expired = [k for k, v in _replay_window.items() if v < now]
        for k in expired:
            del _replay_window[k]

def _cleanup_loop():
    while True:
        time.sleep(30)
        clean_replay_window()

threading.Thread(target=_cleanup_loop, daemon=True).start()


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
        host="10.40.91.184",   # gateway faces the network
        port=5100,
        ssl_context=ssl_context,
        debug=False
    )