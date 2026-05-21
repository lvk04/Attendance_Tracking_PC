"""
ArcFace Face Recognition Engine.
Uses ArcFace ONNX model via OpenCV DNN.
Handles embedding generation, cosine similarity matching, and attendance logging.
"""

import cv2
import numpy as np
import os
import sqlite3
from datetime import datetime


class ArcFaceRecognizer:
    """Face recognition using ArcFace ONNX model."""

    def __init__(self, model_path="MobileFaceNet.onnx"):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(current_dir, model_path)

        self.net = cv2.dnn.readNetFromONNX(full_path)

        self.known_names = []
        self.known_embeddings = []
        self.threshold = 0.55

        self.attendance_db_path = None

    def load_database(self, data_dir):
        """Load all face embeddings from faces.db into memory."""
        faces_db = os.path.join(data_dir, "faces.db")
        self.attendance_db_path = os.path.join(data_dir, "attendance.db")
        self._setup_attendance_db()

        if not os.path.exists(faces_db):
            print("No faces.db found yet.")
            return

        conn = sqlite3.connect(faces_db)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT person_name, embedding FROM user_embeddings")
            rows = cursor.fetchall()

            self.known_names = []
            self.known_embeddings = []

            for row in rows:
                self.known_names.append(row[0])
                self.known_embeddings.append(
                    np.frombuffer(row[1], dtype=np.float32)
                )

            print(f"Loaded {len(self.known_names)} embeddings into memory.")
        except sqlite3.OperationalError:
            print("Database exists but no user_embeddings table found.")
        finally:
            conn.close()

    def get_embedding(self, cropped_face_bgr):
            resized = cv2.resize(cropped_face_bgr, (112, 112))
            blob = cv2.dnn.blobFromImage(
                resized, scalefactor=1.0/127.5, size=(112, 112), 
                mean=(127.5, 127.5, 127.5), swapRB=True
            )
            self.net.setInput(blob)
            emb = self.net.forward()[0]
            
            # Safe L2 Normalization (adds a tiny epsilon value to prevent division by zero)
            return emb / (np.linalg.norm(emb) + 1e-10)

    def cosine_similarity(self, a, b):
        """Cosine similarity between two vectors. 1.0 = identical."""
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    def recognize(self, face_bgr):
        """
        Match a face against known embeddings.
        Returns (name, confidence).
        """
        if not self.known_embeddings:
            return "Unknown", 0.0

        query = self.get_embedding(face_bgr)

        best_name = "Unknown"
        best_sim = -1.0

        for name, emb in zip(self.known_names, self.known_embeddings):
            sim = self.cosine_similarity(query, emb)
            if sim > best_sim:
                best_sim = sim
                best_name = name

        if best_sim >= self.threshold:
            return best_name, best_sim
        return "Unknown", best_sim

    def _setup_attendance_db(self):
        """Create the attendance database if it doesn't exist."""
        if not self.attendance_db_path:
            return
        conn = sqlite3.connect(self.attendance_db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attendance_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_name TEXT,
                timestamp TEXT,
                synced INTEGER DEFAULT 0
            )
        ''')
        conn.commit()
        conn.close()

    def log_attendance(self, name):
        """Log a recognition event to attendance.db."""
        if not self.attendance_db_path:
            return None
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(self.attendance_db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO attendance_logs (person_name, timestamp) VALUES (?, ?)",
            (name, now)
        )
        conn.commit()
        conn.close()
        print(f"Logged attendance: {name} at {now}")
        return now