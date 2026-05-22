import os
import sqlite3
import json
import threading
import time
import base64
import requests
import urllib3
import numpy as np

from requests.exceptions import SSLError

# Suppress SSL warnings for self-signed cert fallback path
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ── Device Identity ───────────────────────────────────────────────────────────
DEVICE_ID        = "device_1_id"
PRIVATE_KEY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "keys", DEVICE_ID, "private_key.pem"
)

USE_HTTPS    = True
GATEWAY_CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gateway.crt")

# ── Faces sync interval (separate from attendance) ────────────────────────────
FACES_SYNC_INTERVAL = 5  #5 seconds


def _load_private_key():
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError(
            f"Private key not found at: {PRIVATE_KEY_PATH}\n"
            f"Run: python generate_device_keys.py --device-id {DEVICE_ID}"
        )
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

_private_key = _load_private_key()


# ── RSA Signing ───────────────────────────────────────────────────────────────
def make_headers(body_str: str) -> dict:
    """
    Sign a request using the device's RSA private key.
    body_str must be the exact string that will be sent as the request body.
    For GET requests with no body, pass an empty string "".
    """
    timestamp = str(int(time.time()))
    message   = f"{DEVICE_ID}.{timestamp}.{body_str}".encode()

    signature = _private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return {
        "Content-Type": "application/json",
        "X-Device-ID":  DEVICE_ID,
        "X-Timestamp":  timestamp,
        "X-Signature":  base64.b64encode(signature).decode(),
    }


def signed_post(url: str, payload: dict, verify) -> requests.Response:
    """Serialize payload once, sign it, send it.

    Tries cert-pinned verification first. Falls back to
    verify=False on SSLError (self-signed cert drift).
    """
    body_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    headers  = make_headers(body_str)
    try:
        return requests.post(url, data=body_str, headers=headers,
                             verify=verify, timeout=10)
    except SSLError:
        if verify:
            print(f"SSL verify failed for {url} — retrying without verification.")
            return requests.post(url, data=body_str, headers=headers,
                                 verify=False, timeout=10)
        raise


def signed_get(url: str, verify) -> requests.Response:
    """Sign a GET request — body is empty string.

    Tries cert-pinned verification first. Falls back to
    verify=False on SSLError (self-signed cert drift).
    """
    headers = make_headers("")
    try:
        return requests.get(url, headers=headers, verify=verify, timeout=10)
    except SSLError:
        if verify:
            print(f"SSL verify failed for {url} — retrying without verification.")
            return requests.get(url, headers=headers, verify=False, timeout=10)
        raise


# ══════════════════════════════════════════════════════════════════════════════
#  ATTENDANCE SYNCER
# ══════════════════════════════════════════════════════════════════════════════

class AttendanceSyncer:
    def __init__(self, db_path, gateway_url, faces_db_path, sync_interval=60.0, recognizer=None):
        self.db_path          = db_path
        self.faces_db_path    = faces_db_path
        self.sync_interval    = sync_interval
        self.recognizer       = recognizer
        self.syncing          = False
        self.running          = False
        self.thread           = None
        self.faces_thread     = None

        # Gateway base URL — all traffic goes through here
        self.gateway_url      = gateway_url.rstrip("/")
        self.attendance_url   = f"{self.gateway_url}/sync"
        self.faces_version_url = f"{self.gateway_url}/faces/version"
        self.faces_download_url = f"{self.gateway_url}/faces/download"
        self.faces_upload_url  = f"{self.gateway_url}/faces/upload"
        self.faces_delete_url  = f"{self.gateway_url}/faces/delete"

        # HTTPS cert verification — pin self-signed gateway cert
        if USE_HTTPS and os.path.exists(GATEWAY_CERT):
            self.verify = GATEWAY_CERT
            print(f"HTTPS enabled. Cert pinned to: {GATEWAY_CERT}")
        elif USE_HTTPS:
            print("WARNING: USE_HTTPS=True but gateway.crt not found — skipping verification.")
            self.verify = False
        else:
            self.verify = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start_syncing(self):
        if self.running:
            return
        self.running = True

        # Attendance sync thread
        self.thread = threading.Thread(target=self._attendance_loop, daemon=True)
        self.thread.start()

        # Faces sync thread — runs independently on its own interval
        self.faces_thread = threading.Thread(target=self._faces_loop, daemon=True)
        self.faces_thread.start()

        print(f"Attendance Syncer started → {self.attendance_url} every {self.sync_interval}s.")
        print(f"Faces Syncer started → {self.faces_version_url} every {FACES_SYNC_INTERVAL}s.")

    def stop_syncing(self):
        self.running = False
        for t in [self.thread, self.faces_thread]:
            if t:
                t.join(timeout=2.0)
        print("Network Syncer stopped.")

    # ── Attendance Loop ───────────────────────────────────────────────────────

    def _attendance_loop(self):
        while self.running:
            self._sync_attendance()
            for _ in range(int(self.sync_interval)):
                if not self.running:
                    break
                time.sleep(1)

    # ── Faces Loop ────────────────────────────────────────────────────────────

    PUSH_RETRY_INTERVAL = 30  # seconds when push fails

    def _faces_loop(self):
        while self.running:
            result = self._push_new_embeddings()
            self._pull_faces_if_outdated(recognizer=self.recognizer)

            if result is False:
                interval = self.PUSH_RETRY_INTERVAL
            else:
                interval = FACES_SYNC_INTERVAL

            for _ in range(interval):
                if not self.running:
                    break
                time.sleep(1)

    # ══════════════════════════════════════════════════════════════════════════
    #  ATTENDANCE SYNC
    # ══════════════════════════════════════════════════════════════════════════

    def _sync_attendance(self):
        if not os.path.exists(self.db_path) or self.syncing:
            return

        self.syncing = True
        try:
            with sqlite3.connect(self.db_path) as conn:
                try:
                    conn.execute(
                        "ALTER TABLE attendance_logs ADD COLUMN synced INTEGER DEFAULT 0"
                    )
                    conn.commit()
                except sqlite3.OperationalError:
                    pass

                rows = conn.execute(
                    "SELECT rowid, person_name, timestamp FROM attendance_logs WHERE synced = 0"
                ).fetchall()

            if not rows:
                return

            pending_ids  = [row[0] for row in rows]
            payload      = {
                "records": [
                    {"person_name": row[1], "timestamp": row[2]} for row in rows
                ]
            }

            response = signed_post(self.attendance_url, payload, self.verify)

            if response.status_code == 200:
                self._mark_attendance_synced(pending_ids)
            else:
                print(f"ATTENDANCE SYNC FAILED: {response.status_code} — {response.text}")

        except requests.RequestException as e:
            print(f"ATTENDANCE SYNC FAILED: {e}. Will retry.")
        except Exception as e:
            print(f"Attendance Sync Error: {e}")
        finally:
            self.syncing = False

    def _mark_attendance_synced(self, pending_ids):
        try:
            with sqlite3.connect(self.db_path) as conn:
                placeholders = ','.join(['?'] * len(pending_ids))
                conn.execute(
                    f"UPDATE attendance_logs SET synced = 1 WHERE rowid IN ({placeholders})",
                    pending_ids
                )
                conn.commit()
            print(f"ATTENDANCE SYNC SUCCESS: {len(pending_ids)} records uploaded.")
        except Exception as e:
            print(f"Failed to mark attendance synced: {e}")

    # ══════════════════════════════════════════════════════════════════════════
    #  FACES PUSH — send new local registrations to host
    # ══════════════════════════════════════════════════════════════════════════

    def _push_new_embeddings(self):
        """Push locally registered embeddings that haven't been uploaded yet.

        Returns:
            None  – nothing to push (no db, no unsynced rows)
            True  – push succeeded (HTTP 200)
            False – push failed (network error, non-200, etc.)
        """
        if not os.path.exists(self.faces_db_path):
            return None

        try:
            with sqlite3.connect(self.faces_db_path) as conn:
                try:
                    conn.execute(
                        "ALTER TABLE user_embeddings ADD COLUMN synced INTEGER DEFAULT 0"
                    )
                    conn.commit()
                except sqlite3.OperationalError:
                    pass

                rows = conn.execute(
                    "SELECT rowid, person_name, embedding FROM user_embeddings WHERE synced = 0"
                ).fetchall()

            if not rows:
                return None

            pending_ids = [row[0] for row in rows]
            embeddings  = [
                {
                    "person_name": row[1],
                    "embedding":   base64.b64encode(row[2]).decode(),
                }
                for row in rows
            ]

            payload = {
                "device_id":  DEVICE_ID,
                "embeddings": embeddings,
            }

            response = signed_post(self.faces_upload_url, payload, self.verify)

            if response.status_code == 200:
                with sqlite3.connect(self.faces_db_path) as conn:
                    placeholders = ','.join(['?'] * len(pending_ids))
                    conn.execute(
                        f"UPDATE user_embeddings SET synced = 1 WHERE rowid IN ({placeholders})",
                        pending_ids
                    )
                    conn.commit()
                result = response.json()
                print(f"FACES PUSH SUCCESS: {len(pending_ids)} embeddings uploaded. Host version now {result.get('version')}.")
                return True
            else:
                print(f"FACES PUSH FAILED: {response.status_code} — {response.text}")
                return False

        except requests.RequestException as e:
            print(f"FACES PUSH FAILED: {e}. Will retry.")
            return False
        except Exception as e:
            print(f"Faces Push Error: {e}")
            return False

    # ══════════════════════════════════════════════════════════════════════════
    #  FACES PULL — download master faces.db if host has newer version
    # ══════════════════════════════════════════════════════════════════════════

    def _get_local_faces_version(self) -> int:
        """Read local faces version. Returns 0 if not found."""
        if not os.path.exists(self.faces_db_path):
            return 0
        try:
            with sqlite3.connect(self.faces_db_path) as conn:
                row = conn.execute(
                    "SELECT version FROM faces_version WHERE id = 1"
                ).fetchone()
            return row[0] if row else 0
        except Exception:
            return 0

    def _update_local_faces_version(self, version: int, updated_at: str):
        """Update the local faces_version table."""
        with sqlite3.connect(self.faces_db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS faces_version (
                    id         INTEGER PRIMARY KEY CHECK (id = 1),
                    version    INTEGER DEFAULT 0,
                    updated_at TEXT    DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('''
                INSERT OR REPLACE INTO faces_version (id, version, updated_at)
                VALUES (1, ?, ?)
            ''', (version, updated_at))
            conn.commit()

    def _pull_faces_if_outdated(self, recognizer=None):
        """
        Check host version. If newer, download all embeddings and
        replace local faces.db content.

        Pass the recognizer instance to hot-reload embeddings into memory
        without restarting the app.
        """
        try:
            # 1. Check host version
            response = signed_get(self.faces_version_url, self.verify)
            if response.status_code != 200:
                print(f"FACES VERSION CHECK FAILED: {response.status_code}")
                return

            data         = response.json()
            host_version = data.get("version", 0)
            updated_at   = data.get("updated_at", "")
            local_version = self._get_local_faces_version()

            if host_version <= local_version:
                return  # already up to date

            print(f"FACES: Host version {host_version} > local {local_version}. Downloading...")

            # 2. Download embeddings
            response = signed_get(self.faces_download_url, self.verify)
            if response.status_code != 200:
                print(f"FACES DOWNLOAD FAILED: {response.status_code}")
                return

            data       = response.json()
            embeddings = data.get("embeddings", [])

            # 3. Preserve unsynced local embeddings so they survive the pull
            unsynced = []
            if os.path.exists(self.faces_db_path):
                try:
                    with sqlite3.connect(self.faces_db_path) as conn:
                        rows = conn.execute(
                            "SELECT person_name, embedding, device_id, registered_at "
                            "FROM user_embeddings WHERE synced = 0"
                        ).fetchall()
                        unsynced = [
                            {
                                "person_name":   r[0],
                                "embedding":     r[1],
                                "device_id":     r[2],
                                "registered_at": r[3],
                            }
                            for r in rows
                        ]
                except sqlite3.OperationalError:
                    pass

            # 4. Replace local faces.db embeddings with master copy
            with sqlite3.connect(self.faces_db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS user_embeddings (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        person_name TEXT,
                        embedding   BLOB,
                        device_id   TEXT,
                        registered_at TEXT,
                        synced      INTEGER DEFAULT 1
                    )
                ''')

                conn.execute("DELETE FROM user_embeddings WHERE synced = 1")

                for emb in embeddings:
                    embedding_bytes = base64.b64decode(emb["embedding"])
                    conn.execute('''
                        INSERT INTO user_embeddings
                            (person_name, embedding, device_id, registered_at, synced)
                        VALUES (?, ?, ?, ?, 1)
                    ''', (
                        emb["person_name"],
                        embedding_bytes,
                        emb.get("device_id", "unknown"),
                        emb.get("registered_at", ""),
                    ))

                # Re-insert unsynced local embeddings that host doesn't have yet
                for emb in unsynced:
                    conn.execute('''
                        INSERT INTO user_embeddings
                            (person_name, embedding, device_id, registered_at, synced)
                        VALUES (?, ?, ?, ?, 0)
                    ''', (
                        emb["person_name"],
                        emb["embedding"],
                        emb["device_id"],
                        emb["registered_at"],
                    ))

                conn.commit()

            # 5. Update local version
            self._update_local_faces_version(host_version, updated_at)

            total = len(embeddings) + len(unsynced)
            print(f"FACES PULL SUCCESS: {total} embeddings ({len(unsynced)} local unsynced preserved). Local version now {host_version}.")

            # 6. Hot-reload recognizer if provided
            if recognizer is not None:
                recognizer.load_database(os.path.dirname(self.faces_db_path))
                print("FACES: Recognizer hot-reloaded.")

        except requests.RequestException as e:
            print(f"FACES PULL FAILED: {e}. Will retry.")
        except Exception as e:
            print(f"Faces Pull Error: {e}")

    # ══════════════════════════════════════════════════════════════════════════
    #  FACES DELETE — sync deletion to host
    # ══════════════════════════════════════════════════════════════════════════

    def push_delete(self, person_name: str):
        """
        Called from app.py when a user is deleted locally.
        Pushes the deletion to host so all other devices sync it.
        """
        payload = {
            "device_id":   DEVICE_ID,
            "person_name": person_name,
        }
        try:
            response = signed_post(self.faces_delete_url, payload, self.verify)
            if response.status_code == 200:
                print(f"FACES DELETE SYNC: '{person_name}' deleted on host.")
            else:
                print(f"FACES DELETE FAILED: {response.status_code} — {response.text}")
        except requests.RequestException as e:
            print(f"FACES DELETE FAILED: {e}")