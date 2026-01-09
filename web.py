# webcam_security_app.py
# Updated: Removed secured apps and enhanced UI/UX.
# Requirements: Python3.9+, opencv-python, pillow, bcrypt
# Run on Windows for registry functionality.
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import webbrowser
from PIL import Image, ImageTk
import tempfile
import os
import time
import winreg
import string
import secrets
import smtplib, ssl, threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

import sqlite3
import bcrypt
import cv2
import numpy as np
import json
from pathlib import Path
import subprocess
import socket
import sys
import traceback

# ===============================
# Global / Paths / Config
# ===============================
APP_NAME = "Webcam Security Dashboard"
log_file = "camera_log.txt"

FACE_DATA_DIR = Path("faces")
FACE_DATA_DIR.mkdir(exist_ok=True)
MODEL_PATH = Path("face_model.yml")
LABELS_PATH = Path("labels.json")

REQUIRE_FACE = True
CONFIDENCE_THRESHOLD = 55.0  # lower=stricter

DB_PATH = "users2.db"

INTRUDER_DIR = Path("intruder_clips")
INTRUDER_DIR.mkdir(exist_ok=True)

# Email (SMTP) configuration (note: keep credentials private)
# Email (SMTP) configuration (note: keep credentials private)
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465  # SSL
SENDER_EMAIL = "kavya0002u@gmail.com"
SENDER_APP_PASSWORD = "vvyxayqfnmgwscez"
ALERT_TO = "kavya002u@gmail.com"  # can be email-to-sms or email  # can be email-to-sms or email

FAILED_TRY_THRESHOLD = 3
_failed_try_count = 0

# Paths for the external camera control scripts (must be in the same directory)
VBS_RUNNER = "run_as_admin.vbs"
DISABLE_BAT = "disable_cam.bat"
ENABLE_BAT = "enable_cam.bat"

# ===============================
# Session (persistent sign-in)
# ===============================
current_user = {"username": None, "is_admin": False, "enrolled": False}

# ===============================
# Utilities
# ===============================
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def log_action(action):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, "a", encoding="utf-8") as log:
        log.write(f"{ts} | {action}\n")

def _timestamp():
    return time.strftime("%Y%m%d_%H%M%S")

def safe_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "UNKNOWN"

# ===============================
# Email helpers
# ===============================
def _build_email(subject: str, body: str, attachments=None) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = ALERT_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    attachments = attachments or []
    for p in attachments:
        try:
            with open(p, "rb") as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(p))
            part["Content-Disposition"] = f'attachment; filename="{os.path.basename(p)}"'
            msg.attach(part)
        except Exception as e:
            print(f"[EMAIL WARN] Could not attach {p!r}: {e}")
    return msg

def _send_email_sync(msg: MIMEMultipart):
    socket.setdefaulttimeout(25)
    def try_ssl_465():
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, 465, context=context, timeout=25) as server:
            server.ehlo()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.send_message(msg)

    def try_starttls_587():
        with smtplib.SMTP(SMTP_HOST, 587, timeout=25) as server:
            server.ehlo()
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.send_message(msg)

    last_err = None
    for attempt in range(1, 4):
        try:
            try_ssl_465()
            return
        except Exception as e1:
            last_err = e1
            try:
                try_starttls_587()
                return
            except Exception as e2:
                last_err = (e1, e2)
        time.sleep(2 * attempt)
    raise RuntimeError(f"SMTP failed after retries: {last_err}")

def send_email(subject: str, body: str, attachments=None, on_fail_show_message=True):
    attachments = attachments or []
    def _worker():
        try:
            m = _build_email(subject, body, attachments)
            _send_email_sync(m)
            print("[EMAIL] Sent:", subject)
            log_action(f"Email sent: {subject}")
        except Exception as e:
            print(f"[EMAIL ERROR] {e!r}")
            log_action(f"Email failed: {e}")
            if on_fail_show_message:
                try:
                    root.after(0, lambda: messagebox.showerror(
                        "Email Error",
                        "Could not send alert email.\nCheck network/antivirus and SMTP settings.\nSee console for details."
                    ))
                except Exception:
                    pass
    threading.Thread(target=_worker, daemon=True).start()

def _email_intruder_report(title:str, detected_name, confidence, attachments=None, extra_info=None):
    """Generic intruder report for any critical action attempt."""
    attachments = attachments or []
    extra_info = extra_info or {}
    body_lines = [
        f"Intruder Alert — {title}",
        f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Host: {safe_hostname()}",
        f"Current app user: {current_user.get('username') or 'None'}",
        f"Detected name: {detected_name}",
        f"Confidence: {confidence:.1f}" if isinstance(confidence, float) else f"Confidence: {confidence}",
        ""
    ]
    for k,v in extra_info.items():
        body_lines.append(f"{k}: {v}")
    body_lines.append("")
    body_lines.append(f"Files attached: {', '.join([os.path.basename(p) for p in attachments]) if attachments else 'none'}")
    body = "\n".join(body_lines)
    send_email(subject=f"Intruder Alert: {title}", body=body, attachments=attachments)

# ===============================
# Windows Webcam privacy registry (HKCU - User Level)
# ===============================
HKCU_WEBCAM_PATH = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"

def _ensure_webcam_key_hkcu():
    winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, HKCU_WEBCAM_PATH, 0,
                       winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)

def set_webcam_value_hkcu(value: str):
    _ensure_webcam_key_hkcu()
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, HKCU_WEBCAM_PATH, 0,
                             winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, value)
    winreg.CloseKey(key)

def get_webcam_value_hkcu() -> str:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, HKCU_WEBCAM_PATH, 0,
                             winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        v, _ = winreg.QueryValueEx(key, "Value")
        winreg.CloseKey(key)
        return v
    except FileNotFoundError:
        return "Allow"
    except Exception:
        return "Unknown"

# ===============================
# Windows Webcam privacy registry (HKLM - System Level - Elevated)
# ===============================
def _run_elevated_command(batch_file_name: str, action_label: str):
    """Launches a batch script via VBS for elevated execution."""
    vbs_path = Path(VBS_RUNNER)
    batch_path = Path(batch_file_name)
    current_dir = Path.cwd()

    if not vbs_path.exists() or not batch_path.exists():
        messagebox.showerror("Error", f"Required script files not found:\n{VBS_RUNNER} or {batch_file_name}")
        return False

    try:
        subprocess.Popen([
            "cscript.exe",
            "//nologo",
            str(vbs_path),
            str(batch_path.resolve()),
            str(current_dir.resolve())
        ], shell=False)
        log_action(f"Requested elevated execution of {batch_file_name} for {action_label}")
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Failed to launch elevated command for {action_label}:\n{e}")
        return False

def system_disable_camera():
    return _run_elevated_command(DISABLE_BAT, "System Camera Disable")

def system_enable_camera():
    return _run_elevated_command(ENABLE_BAT, "System Camera Enable")

# ===============================
# Status Check Function
# ===============================
def check_all_webcam_status():
    """Checks and displays both HKCU (User) and HKLM (System) status."""
    
    # 1. Check HKCU Status (User-level)
    hkcu_status = get_webcam_value_hkcu()
    hkcu_detail = f"User Level (HKCU):\nStatus: {hkcu_status}"

    # 2. Check HKLM Status (System-level)
    hklm_status = "Unknown (Access Denied)"
    HKLM_WEBCAM_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, HKLM_WEBCAM_PATH, 0,
                             winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        v, t = winreg.QueryValueEx(key, "Value")
        winreg.CloseKey(key)
        hklm_status = "System Disabled (Value=0)" if v == 0 else f"System Enabled (Value={v}, Type={t})"
    except FileNotFoundError:
        hklm_status = "System Enabled (Key Not Present/Default)"
    except Exception:
        hklm_status = f"System Error: Cannot read HKLM registry directly."
    
    hklm_detail = f"System Level (HKLM):\nStatus: {hklm_status}"

    messagebox.showinfo("Webcam Status Check",
                        f"--- Webcam Privacy Status ---\n\n"
                        f"{hkcu_detail}\n\n"
                        f"{hklm_detail}\n\n"
                        f"Note: System Controls require Admin rights (UAC).")

# ===============================
# DB: users
# ===============================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        face_dir TEXT,
        is_admin INTEGER DEFAULT 0,
        enrolled INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    # Ensure columns exist (for backward compatibility)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    except: pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN enrolled INTEGER DEFAULT 0")
    except: pass
    conn.commit()
    conn.close()

def add_user(username: str, password: str, face_dir: str = None, is_admin: bool = False, enrolled: bool = False):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, face_dir, is_admin, enrolled) VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, face_dir, int(bool(is_admin)), int(bool(enrolled)))
        )
        conn.commit()
        log_action(f"DB: user added {username}")
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def set_user_face_dir(username: str, face_dir: str, mark_enrolled: bool = True):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE users SET face_dir=?, enrolled=? WHERE username=?", (face_dir, int(bool(mark_enrolled)), username))
    conn.commit()
    conn.close()

def set_user_enrolled(username: str, enrolled: bool = True):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE users SET enrolled=? WHERE username=?", (int(bool(enrolled)), username))
    conn.commit()
    conn.close()

def authenticate_user(username: str, password: str):
    """Return (ok:bool, is_admin:bool, enrolled:bool)."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, is_admin, enrolled FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False, False, False
    pw_hash, is_admin, enrolled = row
    try:
        ok = bcrypt.checkpw(password.encode(), pw_hash.encode())
    except Exception:
        ok = False
    return ok, bool(is_admin), bool(enrolled)

def ensure_bootstrap_admin():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    conn.close()
    if count == 0:
        admin_pw = generate_password(14)
        add_user("admin", admin_pw, face_dir=str((FACE_DATA_DIR / "admin").as_posix()), is_admin=True, enrolled=False)
        print(f"[BOOTSTRAP] Admin account created -- Username: admin  Password: {admin_pw}")
        try:
            messagebox.showinfo("Bootstrap Admin",
                                 f"No users found.\nCreated **admin** account.\n\nUsername: admin\nPassword: {admin_pw}\n\nPlease sign in and enroll the admin face.")
        except Exception:
            pass

# ===============================
# Face Recognition helpers
# ===============================
def _load_labels():
    if LABELS_PATH.exists():
        try:
            return json.loads(LABELS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _save_labels(labels):
    LABELS_PATH.write_text(json.dumps(labels), encoding="utf-8")

def _detect_faces(gray):
    cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    return cascade.detectMultiScale(gray, scaleFactor=1.2, minNeighbors=5, minSize=(80, 80))

def train_face_model():
    images, labels = [], []
    name_to_id, next_id = {}, 0

    for user_dir in FACE_DATA_DIR.iterdir():
        if not user_dir.is_dir(): continue
        name = user_dir.name
        if name not in name_to_id:
            name_to_id[name] = next_id; next_id += 1
        for img_path in user_dir.glob("*.png"):
            img = cv2.imread(str(img_path), cv2.IMREAD_GRAYSCALE)
            if img is None: continue
            images.append(img); labels.append(name_to_id[name])

    if not images:
        try:
            messagebox.showwarning("Train", "No face data to train. Enroll a user first.")
        except Exception:
            print("[TRAIN] No face data to train.")
        return False

    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.train(images, np.array(labels))
    recognizer.write(str(MODEL_PATH))

    labels_map = {str(v): k for k, v in name_to_id.items()}
    _save_labels(labels_map)
    log_action("Face model trained")
    return True

def enroll_face(username: str):
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    if not cap.isOpened():
        messagebox.showerror("Camera", "Could not access camera (Code 0).")
        return

    user_dir = FACE_DATA_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)

    saved, target = 0, 30
    cv2.namedWindow("Enroll", cv2.WINDOW_NORMAL)
    try:
        while saved < target:
            ret, frame = cap.read()
            if not ret: break
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = _detect_faces(gray)
            
            status_text = f"Capturing: {saved}/{target} images."
            text_color = (0, 255, 255) # Yellow/Cyan
            
            for (x, y, w, h) in faces:
                face = cv2.resize(gray[y:y+h, x:x+w], (200, 200))
                cv2.imwrite(str(user_dir / f"{username}_{saved:03d}.png"), face)
                saved += 1
                
                # Draw green rectangle for captured face
                cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
                status_text = f"Captured {saved} images..."
                text_color = (0, 255, 0) # Green
                break
            
            # Display status text
            cv2.putText(frame, status_text, (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.8, text_color, 2)
            cv2.putText(frame, "Press Q to abort.", (10, 60),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)

            cv2.imshow("Enroll", frame)
            if cv2.waitKey(100) & 0xFF == ord('q'):
                break
            time.sleep(0.1) # Add a small delay to prevent rapid capture
    finally:
        cap.release()
        cv2.destroyAllWindows()

    if saved < target * 0.5:
        messagebox.showwarning("Enroll", f"Only captured {saved} images. Training cancelled. Try again with better lighting and positioning.")
        return

    # Set face_dir regardless of enrollment success for logging
    set_user_face_dir(username, str(user_dir), mark_enrolled=False)

    if train_face_model():
        set_user_enrolled(username, True)
        show_success(f"Enrolled **{username}** ({saved} imgs) & trained model successfully!")
        log_action(f"Face enrolled: {username} ({saved} samples)")
    else:
        messagebox.showwarning("Enroll", "Training failed. Not marked as enrolled.")

def _load_recognizer_and_labels():
    if not MODEL_PATH.exists() or not LABELS_PATH.exists():
        return None, None
    try:
        labels_map = {int(k): v for k, v in _load_labels().items()}
        recognizer = cv2.face.LBPHFaceRecognizer_create()
        recognizer.read(str(MODEL_PATH))
        return recognizer, labels_map
    except Exception:
        return None, None

def recognize_and_auth(expected_username: str, timeout_sec: int = 10):
    """Return (ok, name, conf). ok=True if recognized under threshold AND name==expected_username."""
    recognizer, labels_map = _load_recognizer_and_labels()
    if recognizer is None:
        messagebox.showwarning("Face Verify", "No trained model found. Enroll a face first.")
        return False, None, 999.0

    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    if not cap.isOpened():
        messagebox.showerror("Camera", "Could not access camera (Code 1).")
        return False, None, 999.0

    start = time.time()
    name, conf, ok = None, 999.0, False
    cv2.namedWindow("Face Verify", cv2.WINDOW_NORMAL)
    try:
        while time.time() - start < timeout_sec:
            ret, frame = cap.read()
            if not ret: break
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = _detect_faces(gray)
            
            status_text = f"Verifying {expected_username}..."
            text_color = (255, 255, 255) # White

            for (x, y, w, h) in faces:
                face = cv2.resize(gray[y:y+h, x:x+w], (200, 200))
                try:
                    label_id, confidence = recognizer.predict(face)
                    guessed = labels_map.get(label_id, "Unknown")
                    name, conf = guessed, confidence
                    ok = (confidence <= CONFIDENCE_THRESHOLD and guessed == expected_username)
                    
                    color = (0, 255, 0) if ok else (0, 0, 255)
                    cv2.rectangle(frame, (x, y), (x+w, y+h), color, 2)
                    cv2.putText(frame, f"{guessed} ({confidence:.1f})", (x, y-10),
                                 cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)
                    status_text = f"Match: {guessed} (Conf: {confidence:.1f})."
                    if ok: status_text = "ACCESS GRANTED. CLOSING..."
                    text_color = color
                except Exception:
                    pass
                break
            
            cv2.putText(frame, status_text, (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.8, text_color, 2)
            cv2.putText(frame, f"Time left: {timeout_sec - int(time.time() - start)}s (Press Q to cancel)", (10, 60),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)
                        
            cv2.imshow("Face Verify", frame)
            if ok: 
                time.sleep(1)
                break
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
    finally:
        cap.release()
        cv2.destroyAllWindows()

    return ok, name, conf

# ===============================
# Intruder capture helpers
# ===============================
def capture_intruder_photo(frame=None):
    INTRUDER_DIR.mkdir(exist_ok=True)
    ts = _timestamp()
    jpg_path = INTRUDER_DIR / f"intruder_{ts}.jpg"
    if frame is None:
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        if not cap.isOpened():
            return None
        ret, f = cap.read()
        cap.release()
        if not ret:
            return None
        frame = f
    try:
        cv2.imwrite(str(jpg_path), frame)
        return str(jpg_path)
    except Exception:
        return None

def _record_clip_worker(duration_sec=8, fps=20):
    try:
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        if not cap.isOpened():
            return None, None
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 640)
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 480)
        ts = _timestamp()

        out_path = INTRUDER_DIR / f"intruder_{ts}.mp4"
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(str(out_path), fourcc, fps, (width, height))
        if not out.isOpened():
            # Fallback to AVI if MP4 fails (common for OpenCV)
            out_path = INTRUDER_DIR / f"intruder_{ts}.avi"
            fourcc = cv2.VideoWriter_fourcc(*'XVID')
            out = cv2.VideoWriter(str(out_path), fourcc, fps, (width, height))
            if not out.isOpened():
                cap.release()
                return None, None

        start = time.time()
        first_frame = None
        while time.time() - start < duration_sec:
            ret, frame = cap.read()
            if not ret:
                break
            if first_frame is None:
                first_frame = frame.copy()
            out.write(frame)

        out.release()
        cap.release()

        jpg_path = None
        if first_frame is not None:
            jpg_path = INTRUDER_DIR / f"{out_path.stem}_thumb.jpg"
            try:
                cv2.imwrite(str(jpg_path), first_frame)
            except Exception:
                jpg_path = None

        return str(out_path), (str(jpg_path) if jpg_path else None)
    except Exception as e:
        print(f"[INTRUDER] record error: {e}")
        return None, None

def record_intruder_clip_async(duration_sec=8, fps=20, notify_email=True):
    def worker():
        video, photo = _record_clip_worker(duration_sec, fps)
        if notify_email:
            parts = [p for p in [photo, video] if p]
            body = (f"Intruder recording created at {time.strftime('%Y-%m-%d %H:%M:%S')} on {safe_hostname()}.\n"
                      f"Files: {', '.join(parts) if parts else 'none'}\n")
            send_email(subject="Intruder Alert: Recording Saved",
                        body=body,
                        attachments=parts)
    threading.Thread(target=worker, daemon=True).start()

def open_intruder_folder():
    INTRUDER_DIR.mkdir(exist_ok=True)
    try:
        os.startfile(str(INTRUDER_DIR))
    except Exception as e:
        messagebox.showerror("Open Folder", f"Could not open folder:\n{e}")

# ===============================
# Webcam registry monitor (spyware detection)
# ===============================
def _monitor_webcam_registry(poll_interval_sec: float = 3.0):
    """Monitors the HKCU (User-Level) registry setting."""
    try:
        last = get_webcam_value_hkcu()
    except Exception:
        last = "Allow"
    while True:
        try:
            cur = get_webcam_value_hkcu()
            if cur != last:
                log_action(f"Webcam HKCU registry changed: {last} -> {cur}")
                if last == "Deny" and cur == "Allow":
                    # sudden enable => possible unauthorized activation
                    video, photo = _record_clip_worker(duration_sec=8, fps=20)
                    attachments = [p for p in [photo, video] if p]
                    extra_info = {"RegistryChange": f"{last} -> {cur}"}
                    _email_intruder_report("Webcam HKCU Enabled Unexpectedly", detected_name="Unknown", confidence="N/A", attachments=attachments, extra_info=extra_info)
                last = cur
        except Exception as e:
            print(f"[REG MON] error: {e}")
        time.sleep(poll_interval_sec)

# ===============================
# UI (Tkinter) - Generic functions
# ===============================
current_view = None
main_content = None # Placeholder for the main content frame

def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()

def show_success(message):
    messagebox.showinfo("Success", message)

def sign_out():
    global current_user
    current_user = {"username": None, "is_admin": False, "enrolled": False}
    refresh_session_label()
    show_view("dashboard")
    messagebox.showinfo("Signed Out", "You have been securely signed out.")

def show_view(view_name):
    global current_view
    if current_view == view_name:
        return

    current_view = view_name
    clear_frame(main_content)

    if view_name == "dashboard":
        show_dashboard(main_content)
    elif view_name == "gallery":
        show_gallery(main_content)
    elif view_name == "users":
        show_users(main_content)
    elif view_name == "logs":
        show_logs(main_content)

# Placeholder functions for other views/dialogs
def show_gallery(container):
    ttk.Label(container, text="Intruder Evidence Gallery", style="Title.TLabel").pack(pady=(40, 20))
    
    gallery_frame = ttk.Frame(container, style="Card.TFrame", padding=30)
    gallery_frame.pack(pady=10, padx=50, fill="x")
    
    ttk.Label(gallery_frame, text="All photos and clips captured due to failed login attempts, failed face verifications, or registry changes are stored here.", style="Card.TLabel").pack(pady=10)
    
    open_btn = ttk.Button(gallery_frame, text="Open Intruder Clips Folder", command=open_intruder_folder, style="Primary.TButton")
    open_btn.pack(pady=20, padx=50, ipadx=20)

def show_users(container):
    ttk.Label(container, text="User and Face Management", style="Title.TLabel").pack(pady=(40, 20))
    
    user_card = ttk.Frame(container, style="Card.TFrame", padding=30)
    user_card.pack(pady=15, padx=50, fill="x")
    
    username = current_user.get('username')
    
    if not username:
        ttk.Label(user_card, text="Please sign in to manage your profile.", style="Header.TLabel").pack(pady=10)
        return
        
    enroll_status = "**ENROLLED**" if current_user.get("enrolled") else "**NOT ENROLLED** (Action Required)"
    
    ttk.Label(user_card, text=f"Active User: {username}", style="Header.TLabel").pack(anchor="w")
    ttk.Label(user_card, text=f"Admin Status: {'Yes' if current_user.get('is_admin') else 'No'}", style="Card.TLabel").pack(anchor="w", pady=(5, 10))
    
    ttk.Label(user_card, text=f"Face Recognition Status: {enroll_status}", style="Card.TLabel", foreground="#ff6b6b" if not current_user.get("enrolled") else "#3b82f6").pack(anchor="w", pady=10)
    
    enroll_btn = ttk.Button(user_card, text="Enroll/Retrain Face for Current User", command=lambda: enroll_face(username), style="Primary.TButton")
    enroll_btn.pack(pady=15, padx=50, ipadx=20)

def show_logs(container):
    ttk.Label(container, text="System Activity and Intruder Logs", style="Title.TLabel").pack(pady=(40, 20), anchor="w", padx=50)
    
    text_frame = ttk.Frame(container, style="Card.TFrame", padding=1)
    text_frame.pack(fill="both", expand=True, padx=50, pady=10)
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            log_text = f.read()
    except FileNotFoundError:
        log_text = "Log file not found."
    
    scrollbar = ttk.Scrollbar(text_frame)
    scrollbar.pack(side="right", fill="y")
    
    # Use a raw Text widget for log display for better control over text style
    log_area = tk.Text(text_frame, wrap="word", yscrollcommand=scrollbar.set, bg="#111827", fg="#e6eef8", font=("Consolas", 10), bd=0, relief="flat", padx=15, pady=15)
    log_area.insert("end", log_text)
    log_area.config(state="disabled")
    log_area.pack(side="left", fill="both", expand=True)
    scrollbar.config(command=log_area.yview)

def sign_in_dialog():
    def on_attempt(u, p):
        global current_user, _failed_try_count 

        ok, is_admin, enrolled = authenticate_user(u, p)
        if ok:
            current_user = {"username": u, "is_admin": is_admin, "enrolled": enrolled}
            _failed_try_count = 0
            show_success(f"Sign in successful for {u}!")
            refresh_session_label()
            top.destroy()
        else:
            _failed_try_count += 1
            log_action(f"Failed login attempt for {u}. Count: {_failed_try_count}")
            messagebox.showerror("Login Failed", "Invalid username or password.")
            if _failed_try_count >= FAILED_TRY_THRESHOLD:
                log_action(f"Intruder Alert: Excessive failed logins.")
                threading.Thread(target=lambda: send_email("Intruder Alert: Failed Logins", f"Excessive failed login attempts on {safe_hostname()}. Last attempt for user: {u}", on_fail_show_message=True)).start()

    top = tk.Toplevel(root, bg="#111827")
    top.title("Sign In")
    top.geometry("380x300")
    top.resizable(False, False)
    top.transient(root)
    top.grab_set()

    main_frame = ttk.Frame(top, style="TFrame", padding=20)
    main_frame.pack(fill="both", expand=True)

    ttk.Label(main_frame, text="ACCESS ACCOUNT", style="Header.TLabel").pack(pady=(5, 20))
    
    ttk.Label(main_frame, text="Username:", style="Card.TLabel").pack(pady=(0, 2), anchor="w")
    user_entry = ttk.Entry(main_frame, width=40, style="Modern.TEntry")
    user_entry.pack(pady=(0, 10))
    
    ttk.Label(main_frame, text="Password:", style="Card.TLabel").pack(pady=(0, 2), anchor="w")
    pass_entry = ttk.Entry(main_frame, width=40, show="*", style="Modern.TEntry")
    pass_entry.pack(pady=(0, 15))

    def login_action():
        on_attempt(user_entry.get(), pass_entry.get())
        
    user_entry.bind('<Return>', lambda e: login_action())
    pass_entry.bind('<Return>', lambda e: login_action())
    user_entry.focus_set()

    ttk.Button(main_frame, text="Sign In", command=login_action, style="Primary.TButton").pack(fill="x", pady=5)
    ttk.Button(main_frame, text="Create New Account", command=lambda: [top.destroy(), sign_up_dialog()], style="Secondary.TButton").pack(fill="x", pady=5)
    
def sign_up_dialog():
    def on_attempt(u, p, is_admin):
        if len(u) < 3 or len(p) < 6:
            messagebox.showerror("Error", "Username must be 3+ chars, Password 6+ chars.")
            return
        
        if add_user(u, p, is_admin=is_admin):
            show_success(f"User **{u}** created! Please sign in and enroll your face.")
            top.destroy()
        else:
            messagebox.showerror("Error", "Username already exists.")

    top = tk.Toplevel(root, bg="#111827")
    top.title("Sign Up")
    top.geometry("380x350")
    top.resizable(False, False)
    top.transient(root)
    top.grab_set()
    
    main_frame = ttk.Frame(top, style="TFrame", padding=20)
    main_frame.pack(fill="both", expand=True)

    ttk.Label(main_frame, text="CREATE NEW ACCOUNT", style="Header.TLabel").pack(pady=(5, 20))

    ttk.Label(main_frame, text="Username (3+ chars):", style="Card.TLabel").pack(pady=(0, 2), anchor="w")
    user_entry = ttk.Entry(main_frame, width=40, style="Modern.TEntry")
    user_entry.pack(pady=(0, 10))
    
    ttk.Label(main_frame, text="Password (6+ chars):", style="Card.TLabel").pack(pady=(0, 2), anchor="w")
    pass_entry = ttk.Entry(main_frame, width=40, show="*", style="Modern.TEntry")
    pass_entry.pack(pady=(0, 10))
    
    is_admin_var = tk.BooleanVar()
    ttk.Checkbutton(main_frame, text="Create as Admin Account", variable=is_admin_var, style="Modern.TCheckbutton").pack(pady=10, anchor="w")

    def signup_action():
        on_attempt(user_entry.get(), pass_entry.get(), is_admin_var.get())
        
    ttk.Button(main_frame, text="Sign Up", command=signup_action, style="Primary.TButton").pack(fill="x", pady=5)


# ===============================
# show_dashboard function and helpers
# ===============================
def _handle_camera_change(target_value: str, action_label: str):
    """Generic function to handle HKCU camera enable/disable with face auth."""
    if not current_user["username"]:
        messagebox.showwarning("Auth", f"Please **sign in** to {action_label.lower()} camera.")
        return

    if not current_user.get("enrolled"):
        messagebox.showwarning("Enrollment Required", "Your face is not enrolled. You must enroll first to use this security feature.")
        log_action(f"Camera control attempt failed: {action_label} by unenrolled user {current_user['username']}")
        return

    # 1. Face verification check
    ok, who, conf = recognize_and_auth(current_user["username"], timeout_sec=10)
    
    if not ok:
        log_action(f"Intruder Attempt: Camera {action_label} denied (detected={who}, conf={conf:.1f})")
        
        # Record clip on failed auth for critical action
        video, photo = _record_clip_worker(duration_sec=8, fps=20)
        attachments = [p for p in [photo, video] if p]
        extra_info = {"ActionAttempt": f"Camera {action_label}"}
        _email_intruder_report("Camera Control Access Blocked", detected_name=who or "Unknown", confidence=conf, attachments=attachments, extra_info=extra_info)

        messagebox.showwarning("Auth Denied", f"Face not recognized for user '{current_user['username']}'. Access denied and evidence captured.")
        return
    else:
        log_action(f"Access Granted: Camera {action_label} by {current_user['username']} (conf={conf:.1f})")
        send_email(
            subject="Webcam Tool: Facial Recognition OK",
            body=(f"Face verification OK for user={current_user['username']} at {time.strftime('%Y-%m-%d %H:%M:%S')} on {safe_hostname()}. \nAction: Camera {action_label}\nConfidence={conf:.1f}"),
            attachments=[]
        )

    try:
        set_webcam_value_hkcu(target_value)
        show_success(f"Camera **{action_label}** Successfully")
        send_email(
            subject=f"Webcam Tool: Webcam {action_label}",
            body=f"Webcam was {action_label.upper()} at {time.strftime('%Y-%m-%d %H:%M:%S')} on {safe_hostname()} by {current_user['username']}.",
            attachments=[]
        )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to {action_label.lower()} camera: {e}")

def button_disable_camera():
    _handle_camera_change("Deny", "Disabled")

def button_enable_camera():
    _handle_camera_change("Allow", "Enabled")

def show_dashboard(container):
    clear_frame(container)

    # Hero Title
    ttk.Label(container, text="SECURITY DASHBOARD", style="Title.TLabel").pack(pady=(40, 20))

    # Main column frame
    main_column = ttk.Frame(container, style="TFrame")
    main_column.pack(fill="x", padx=50, pady=10)

    # --- Card 1: Webcam Control (HKCU) ---
    webcam_card = ttk.Frame(main_column, style="Card.TFrame", padding=30)
    webcam_card.pack(fill="x", pady=15)
    
    ttk.Label(webcam_card, text="Webcam Privacy Control (User Level)", style="Header.TLabel").pack(anchor="w", pady=(0, 5))
    ttk.Label(webcam_card, text="Toggle the camera privacy setting (HKCU). This action requires facial verification.", style="Card.TLabel", wraplength=700).pack(anchor="w", pady=(0, 15))

    btn_frame_hkcu = ttk.Frame(webcam_card, style="TFrame")
    btn_frame_hkcu.pack(anchor="w", pady=10)
    
    ttk.Button(btn_frame_hkcu, text="Disable Camera (Deny)", command=button_disable_camera, style="Danger.TButton").pack(side="left", padx=(0, 20), ipadx=10)
    ttk.Button(btn_frame_hkcu, text="Enable Camera (Allow)", command=button_enable_camera, style="Primary.TButton").pack(side="left", padx=(0, 20), ipadx=10)
    ttk.Button(btn_frame_hkcu, text="Check Current Status", command=check_all_webcam_status, style="Secondary.TButton").pack(side="left", ipadx=10)

    # System-Level Controls section
    ttk.Label(webcam_card, text="System-Wide Control (HKLM - Requires UAC/Admin rights)", style="Card.TLabel", font=("Segoe UI", 10, "italic"), foreground="#ff6b6b").pack(anchor="w", pady=(20, 5))
    system_btn_frame = ttk.Frame(webcam_card, style="TFrame")
    system_btn_frame.pack(anchor="w")
    ttk.Button(system_btn_frame, text="System-Wide DISABLE", command=system_disable_camera, style="Danger.TButton").pack(side="left", padx=(0, 20), ipadx=10)
    ttk.Button(system_btn_frame, text="System-Wide ENABLE", command=system_enable_camera, style="Primary.TButton").pack(side="left", padx=(0, 0), ipadx=10)


    # --- Card 2: Intruder Tools ---
    intruder_card = ttk.Frame(main_column, style="Card.TFrame", padding=30)
    intruder_card.pack(fill="x", pady=15)
    
    ttk.Label(intruder_card, text="Intruder Evidence & Logging", style="Header.TLabel").pack(anchor="w", pady=(0, 5))
    ttk.Label(intruder_card, text="Manually capture test evidence or review all recorded intruder attempts.", style="Card.TLabel", wraplength=700).pack(anchor="w", pady=(0, 15))

    intruder_btn_frame = ttk.Frame(intruder_card, style="TFrame")
    intruder_btn_frame.pack(anchor="w", pady=10)
    
    ttk.Button(intruder_btn_frame, text="Record Test Intruder Clip", command=lambda: record_intruder_clip_async(notify_email=True), style="Danger.TButton").pack(side="left", padx=(0, 20), ipadx=10)
    ttk.Button(intruder_btn_frame, text="Open Intruder Gallery", command=open_intruder_folder, style="Primary.TButton").pack(side="left", padx=(0, 0), ipadx=10)


# ===============================
# UI (Tkinter) - Setup and Styling
# ===============================
root = tk.Tk()
root.title(APP_NAME)
root.geometry("1000x800")
root.configure(bg="#0b1220") 

# --- Setup ttk style for enhanced UI ---
style = ttk.Style(root)
style.theme_use('clam')

# Primary colors
BG_PRIMARY = "#0b1220"
BG_CARD = "#111827"
TEXT_LIGHT = "#e6eef8"
TEXT_ACCENT = "#9ca3af"
BUTTON_PRIMARY = "#3b82f6"
BUTTON_DANGER = "#ef4444"
BUTTON_SECONDARY = "#4b5563"

# Main frames and background
style.configure("TFrame", background=BG_PRIMARY)
style.configure("Card.TFrame", background=BG_CARD, relief="flat", borderwidth=1, bordercolor="#1f2937")

# Text styles
style.configure("Title.TLabel", font=("Segoe UI", 24, "bold"), foreground="#ff6b6b", background=BG_PRIMARY)
style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground=TEXT_LIGHT, background=BG_CARD)
style.configure("Card.TLabel", font=("Segoe UI", 11), foreground=TEXT_ACCENT, background=BG_CARD)
style.configure("Nav.TLabel", font=("Segoe UI", 10), foreground=TEXT_ACCENT, background=BG_PRIMARY)

# Button styles
style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=[15, 10], borderwidth=0, relief="flat", foreground=TEXT_LIGHT)
style.configure("Primary.TButton", background=BUTTON_PRIMARY)
style.map("Primary.TButton", background=[('active', '#2563eb'), ('disabled', '#60a5fa')])

style.configure("Danger.TButton", background=BUTTON_DANGER)
style.map("Danger.TButton", background=[('active', '#dc2626'), ('disabled', '#f87171')])

style.configure("Secondary.TButton", background=BUTTON_SECONDARY)
style.map("Secondary.TButton", background=[('active', '#374151'), ('disabled', '#9ca3af')])

# Entry/Input styles
style.configure("Modern.TEntry", fieldbackground="#1f2937", foreground=TEXT_LIGHT, borderwidth=1, bordercolor="#374151", relief="flat", insertcolor=TEXT_LIGHT, padding=5)
style.map("Modern.TEntry", fieldbackground=[('focus', '#2563eb')], bordercolor=[('focus', '#3b82f6')])

# Checkbutton style
style.configure("Modern.TCheckbutton", background=BG_CARD, foreground=TEXT_ACCENT, font=("Segoe UI", 10), indicatorrelief="flat")
style.map("Modern.TCheckbutton", background=[('active', BG_CARD)], foreground=[('active', TEXT_LIGHT)])


# Top navbar frame (header)
header = ttk.Frame(root, padding=(20,15,20,15), style="Card.TFrame")
header.pack(fill="x", side="top")

# Left: app title
title_lbl = ttk.Label(header, text=APP_NAME, style="Header.TLabel", foreground="#ff6b6b", background=BG_CARD)
title_lbl.pack(side="left", padx=(0, 40))

# Middle: nav buttons
nav_frame = ttk.Frame(header, style="Card.TFrame")
nav_frame.pack(side="left", padx=10)
ttk.Button(nav_frame, text="Dashboard", command=lambda: show_view("dashboard"), style="Secondary.TButton").pack(side="left", padx=8)
ttk.Button(nav_frame, text="Intruder Gallery", command=lambda: show_view("gallery"), style="Secondary.TButton").pack(side="left", padx=8)
ttk.Button(nav_frame, text="Users", command=lambda: show_view("users"), style="Secondary.TButton").pack(side="left", padx=8)
ttk.Button(nav_frame, text="Logs", command=lambda: show_view("logs"), style="Secondary.TButton").pack(side="left", padx=8)

# Right: session info + sign in/out
session_frame = ttk.Frame(header, style="Card.TFrame")
session_frame.pack(side="right")
session_user_lbl = ttk.Label(session_frame, text="Not signed in", style="Card.TLabel", foreground=TEXT_LIGHT, background=BG_CARD)
session_user_lbl.pack(side="left", padx=15)

def refresh_session_label():
    u = current_user.get("username")
    if u:
        session_user_lbl.config(text=f"Signed in: {u} {'(ADMIN)' if current_user.get('is_admin') else ''}")
        sign_btn.config(text="Sign Out", command=sign_out, style="Danger.TButton")
    else:
        session_user_lbl.config(text="Not signed in")
        sign_btn.config(text="Sign In / Up", command=sign_in_dialog, style="Primary.TButton")

sign_btn = ttk.Button(session_frame, text="Sign In / Up", command=lambda: sign_in_dialog(), style="Primary.TButton")
sign_btn.pack(side="left", padx=0)
refresh_session_label()

# Main content area
main_content = ttk.Frame(root, style="TFrame")
main_content.pack(fill="both", expand=True)

# ===============================
# App start: init DB, bootstrap admin
# ===============================
init_db()
ensure_bootstrap_admin()

# Start registry monitor thread
threading.Thread(target=_monitor_webcam_registry, daemon=True).start()

# Show sign-in after short delay
root.after(300, lambda: sign_in_dialog())

# Start the dashboard view
show_view("dashboard")

# Run the Tkinter event loop
root.mainloop()
