#🔐 Webcam Security Dashboard

A Windows-based webcam security and privacy control system that combines facial recognition, system-level access control, and real-time intrusion monitoring to prevent unauthorized camera usage.

The application enables secure webcam enable/disable operations using facial authentication, monitors Windows registry changes for suspicious activity, and automatically captures evidence (photos/videos) and sends email alerts on intrusion attempts.

🚀 Key Features

Facial recognition–based access control using OpenCV (LBPH), ensuring only authorized users can enable or disable the webcam

User-level (HKCU) and system-level (HKLM) webcam control, including elevated admin operations via secure scripts

Real-time registry monitoring to detect unauthorized webcam activation attempts

Automatic intruder evidence capture (images + video clips) with email alerts

Secure authentication system with encrypted credentials (bcrypt) and persistent sessions

Modern desktop UI built with Tkinter, featuring logs, intruder gallery, and role-based access

🛠 Tech Stack

Python, OpenCV, Tkinter

Windows Registry (HKCU / HKLM)

SQLite + bcrypt for secure user management

SMTP email alerts

Batch & VBScript for elevated system controls

🎯 Use Cases

Webcam privacy protection

Insider threat detection

Unauthorized access auditing

Security-focused desktop automation
