# Attendance Tracking System

A distributed face recognition attendance system with RSA-authenticated multi-device support. Edge devices capture faces, a gateway verifies cryptographic signatures, and a central host stores attendance records and face embeddings.

## Architecture

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│   app.py (:5000)    │────▶│  gateway.py (:5100)  │────▶│   host.py (:5050)   │
│  Face Recognition   │     │  RSA auth + proxy    │     │  Attendance + Faces │
│  Web UI (Flask)     │     │  Replay protection   │     │  Master Databases   │
│  YuNet + ArcFace    │     │  Device registry     │     │  Version-tracked    │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘
         │                                                        │
         ▼                                                        ▼
┌─────────────────────┐                                ┌─────────────────────┐
│  data/faces.db      │                                │  master_faces.db    │
│  data/attendance.db │                                │  master_attendance  │
│  (local SQLite)     │                                │  .db  (central)     │
└─────────────────────┘                                └─────────────────────┘
```

## Features

- **Face Detection** — YuNet ONNX model (OpenCV), auto-downloaded on first run
- **Face Recognition** — ArcFace / MobileFaceNet embeddings with cosine similarity
- **Liveness-Quality Checks** — brightness, blur, centering, tilt, face size validation
- **Multi-Device Support** — RSA-PSS signed requests, replay-attack protection
- **Automatic Sync** — attendance logs and face embeddings sync to central host
- **Version-Tracked Faces DB** — edge devices pull only when host version changes
- **Web Dashboard** — attendance logs, user management, face registration UI
- **HTTPS Ready** — self-signed cert generation via included script

## Prerequisites

- Python 3.8+
- OpenCV (`opencv-contrib-python`) — auto-downloads YuNet ONNX model
- OpenSSL (for certificate generation)

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate a device key pair

Run once per edge device:

```bash
python generate_device_keys.py --device-id device_1_id
```

Output:
```
keys/device_1_id/private_key.pem   ← stays on edge device, never share
keys/device_1_id/public_key.pem    ← copy to gateway
```

### 3. Register the device on the gateway

```bash
mkdir -p public_keys
cp keys/device_1_id/public_key.pem public_keys/device_1_id.pem
```

The gateway loads all `.pem` files from `public_keys/` at startup. Each filename (minus `.pem`) becomes a registered device ID.

### 4. Set the host token

```bash
# Linux / Git Bash
export HOST_TOKEN=host_token_123

# Windows CMD
set HOST_TOKEN=host_token_123

# Windows PowerShell
$env:HOST_TOKEN="host_token_123"
```

### 5. (Optional) Generate HTTPS certificate

```bash
# Windows
generate_cert.bat

# Linux / Git Bash
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout gateway.key -out gateway.crt -days 365 \
    -subj "/CN=<YOUR_IP>" \
    -addext "subjectAltName=IP:<YOUR_IP>"
```

Then set `USE_HTTPS = True` in `gateway.py`, `host.py`, and `network_sync.py`.

## Running

Start each service in a separate terminal. The gateway must be reachable from the edge device.

### Terminal 1 — Host (central attendance server)

```bash
python host.py
# Dashboard:   http://127.0.0.1:5050
# Logs:        http://127.0.0.1:5050/logs
# Faces DB:    http://127.0.0.1:5050/faces
```

### Terminal 2 — Gateway (RSA auth proxy)

```bash
python gateway.py
# Health:  http://<GATEWAY_IP>:5100/health
```

### Terminal 3 — App (face recognition UI)

```bash
python app.py
# Open http://127.0.0.1:5000 in a browser
```

## Usage

### Web UI Pages

| Route | Page | Description |
|---|---|---|
| `/` | Home | Navigation hub |
| `/register` | Register | Capture 5 face shots to enroll a new user |
| `/recognize` | Recognize | Live webcam face recognition with attendance logging |
| `/users` | Users | List registered users, view embedding count |
| `/attendance` | Attendance | View today's attendance records |

### Registering a User

1. Open `http://127.0.0.1:5000/register`
2. Enter the person's name and click **Start Registration**
3. Position face in the center — quality checks ensure good captures
4. After 5 successful shots, embeddings are computed and synced to the host
5. All other edge devices automatically pull the new face embeddings

### Recognizing Faces

1. Open `http://127.0.0.1:5000/recognize`
2. Click **Start** to activate the webcam
3. Recognized faces display name, confidence, and a consensus progress bar
4. After 3 consecutive matches, attendance is logged (10-second cooldown)

### API Endpoints

#### App (port 5000)

| Method | Route | Description |
|---|---|---|
| POST | `/api/register/start` | Start a registration session |
| POST | `/api/register/frame` | Submit a face frame during registration |
| POST | `/api/register/finish` | Finalize registration, compute embeddings |
| POST | `/api/recognize/frame` | Submit a frame for recognition |
| POST | `/api/users/delete/<name>` | Delete a user and sync deletion to host |
| GET | `/api/attendance/today` | Get today's attendance records |

#### Gateway (port 5100)

| Method | Route | Description |
|---|---|---|
| GET | `/health` | Health check + list registered devices |
| * | `/*` | All other routes → RSA-verified proxy to host |

#### Host (port 5050)

| Method | Route | Description |
|---|---|---|
| POST | `/sync` | Receive attendance records from gateway |
| GET | `/logs` | Attendance dashboard (HTML) |
| GET | `/faces` | Faces dashboard (HTML) |
| GET | `/faces/version` | Get current faces DB version |
| GET | `/faces/download` | Download all active face embeddings |
| POST | `/faces/upload` | Upload new face embeddings |
| POST | `/faces/delete` | Soft-delete a person's embeddings |

## Security

| Measure | Implementation |
|---|---|
| Transport | HTTP (dev) / HTTPS with self-signed cert (prod) |
| Device auth | RSA-PSS signature over `device_id.timestamp.body` |
| Replay protection | Timestamp freshness (30s window) + signature nonce tracking |
| Host auth | `X-Sync-Token` header set via `HOST_TOKEN` env var |
| Key separation | Private keys stay on edge devices; public keys registered on gateway |
| Face deletion | Soft-delete (`is_active=0`) for audit trail |

## Project Structure

```
project/
├── app.py                       # Face recognition Flask app (port 5000)
├── gateway.py                   # Auth gateway / proxy (port 5100)
├── host.py                      # Central attendance + faces server (port 5050)
├── network_sync.py              # Background sync client (attendance + faces)
│
├── arcface_recognizer.py        # ArcFace ONNX embedding + recognition engine
├── face_detection.py            # YuNet face detector with quality checks
│
├── generate_device_keys.py      # RSA key pair generator (run once per device)
├── generate_cert.bat            # Self-signed HTTPS cert generator (Windows)
│
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git exclusion rules
├── readme.md                    # This file
│
├── templates/                   # Jinja2 HTML templates
│   ├── base.html                # Layout template
│   ├── index.html               # Home page
│   ├── register.html            # Face registration UI
│   ├── recognize.html           # Face recognition UI
│   ├── users.html               # User list
│   └── attendance.html          # Attendance records
│
├── static/
│   ├── css/
│   │   └── style.css            # Application styles
│   └── js/
│       ├── recognize.js         # Webcam recognition client
│       └── register.js          # Face registration client
│
├── models/                      # ONNX model files (auto-downloaded)
│   └── face_detection_yunet_2023mar.onnx
│
├── data/                        # Runtime databases (gitignored)
│   ├── faces.db                 # Local face embeddings (SQLite)
│   ├── attendance.db            # Local attendance logs (SQLite)
│   └── registered_faces/        # Raw face capture images
│
├── keys/                        # Device RSA key pairs (gitignored)
│   └── device_1_id/
│       ├── private_key.pem
│       └── public_key.pem
│
├── public_keys/                 # Registered device public keys (gitignored)
│   └── device_1_id.pem
│
├── master_attendance.db         # Host attendance master (gitignored)
├── master_faces.db              # Host faces master (gitignored)
│
├── gateway.crt                  # HTTPS certificate (generated)
└── gateway.key                  # HTTPS private key (generated, never share)
```

## Adding / Revoking Devices

### Add a new device

```bash
python generate_device_keys.py --device-id cam_lobby
cp keys/cam_lobby/public_key.pem public_keys/cam_lobby.pem
# Restart gateway.py
```

### Revoke a device

```bash
rm public_keys/cam_lobby.pem
# Restart gateway.py — device is immediately blocked
```

## Sync Architecture

### Attendance Sync
- Edge device logs attendance to local `attendance.db`
- `AttendanceSyncer` pushes unsynced records every 60s to the gateway
- Gateway verifies RSA signature and forwards to host
- Host stores records in `master_attendance.db`

### Faces Sync
- New face registrations are pushed to the host immediately
- All edge devices poll `GET /faces/version` every 5 seconds
- When the host version exceeds the local version, embeddings are downloaded
- Unsynced local embeddings are preserved during the pull
- Recognizer hot-reloads without restarting the app

## License

MIT
