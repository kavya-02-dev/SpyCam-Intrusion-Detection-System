# 🔐 Webcam Security Dashboard

A **Windows-based webcam privacy and security system** that combines **facial recognition**, **system-level access control**, and **real-time intrusion detection** to prevent unauthorized camera usage.

The application allows only **verified users** to enable or disable the webcam using **face authentication**, continuously monitors **Windows registry changes**, and automatically **captures evidence (images/videos)** with **email alerts** on suspicious activity.

---

## ✨ Features

* **Facial recognition–based access control** using OpenCV (LBPH) for secure webcam enable/disable actions
* **User-level (HKCU) and system-level (HKLM) webcam control**, including admin-privileged operations
* **Real-time Windows registry monitoring** to detect unauthorized webcam activation
* **Automatic intruder evidence capture** (photos and video clips) with email notifications
* **Secure user authentication** with encrypted credentials (bcrypt) and persistent sessions
* **Modern desktop UI** with dashboard, logs, intruder gallery, and role-based access

---

## 🛠 Tech Stack

* **Python**
* **OpenCV** (Face Recognition – LBPH)
* **Tkinter** (Desktop UI)
* **SQLite** + **bcrypt** (User authentication)
* **Windows Registry (HKCU / HKLM)**
* **SMTP Email Alerts**
* **Batch & VBScript** (Elevated system controls)

---

## 🖥 Platform Support

* **Windows OS**
* Requires **Python 3.9+**
* Admin privileges required for system-level webcam control

---

## 🎯 Use Cases

* Webcam privacy protection
* Unauthorized access detection
* Insider threat monitoring
* Security-focused desktop automation

---

## 🚀 Getting Started

### Prerequisites

```bash
Python 3.9+
pip install opencv-python pillow bcrypt
```

### Run the Application

```bash
python webcam_security_app.py
```

> ⚠️ Ensure the batch (`.bat`) and VBS scripts are present in the same directory for system-level controls.

---

## 📸 How It Works (High Level)

1. User signs in with credentials
2. Facial enrollment trains a recognition model
3. Webcam enable/disable actions require face verification
4. Registry changes are continuously monitored
5. Unauthorized attempts trigger evidence capture and email alerts

---

## 🔒 Security Notes

* Passwords are **hashed using bcrypt**
* Facial data is stored locally
* Email credentials should be stored securely (use environment variables in production)

---

## 📌 Why This Project Matters

This project demonstrates **practical system security engineering**, combining **computer vision**, **OS-level controls**, and **real-time monitoring** to solve a real privacy problem on consumer systems.

---

## 📄 License

This project is for educational and research purposes.


Just say 👍
