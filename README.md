# 🛡️ PHP Reverse Shell Script Detection Tool

A Python-based cybersecurity tool that detects malicious PHP reverse shell scripts using static analysis and regular expression pattern matching. The application automatically scans PHP files, identifies suspicious reverse shell behaviors, quarantines detected files, and sends real-time Telegram alerts to the user.

---

## 📌 Overview

PHP reverse shells are one of the most common techniques used by attackers to gain unauthorized remote access to compromised web servers. Once uploaded to a server, these scripts allow attackers to execute commands remotely and maintain persistent access.

This project provides an automated detection system that scans PHP files for known reverse shell signatures, quarantines suspicious files, logs detection events, and optionally sends Telegram notifications to administrators.

---

## ✨ Features

- 🔍 Detects malicious PHP reverse shell scripts
- 📂 Recursively scans directories
- ⚡ Identifies dangerous PHP functions using regex
- 🚨 Sends instant Telegram alerts
- 📦 Automatically quarantines detected files
- 📝 Maintains detailed scan logs
- 🖥️ Simple GUI built with Tkinter
- ⚙️ Lightweight and easy to use

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| Python | Core Programming Language |
| Tkinter | Desktop GUI |
| Regex | Pattern Matching |
| Requests | Telegram API Integration |
| Python-dotenv | Environment Variable Management |
| Logging | Event Logging |
| OS & Shutil | File Handling and Quarantine |

---

## 📂 Project Structure

```text
REVERSE-SHELL-SCRIPT-DETECTION/
│
├── php_shell_detector.py      # Main application
├── .env                       # Telegram credentials
├── shell_detector.log         # Detection logs
├── quarantine/                # Quarantined malicious files
├── README.md
└── requirements.txt
```

---

## 🚀 Installation

### Clone the repository

```bash
git clone https://github.com/anusreedodle/REVERSE-SHELL-SCRIPT-DETECTION.git
```

### Navigate into the project

```bash
cd REVERSE-SHELL-SCRIPT-DETECTION
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Application

```bash
python php_shell_detector.py
```

The graphical interface will launch, allowing you to select a directory to scan.

---

## 🔍 Detection Process

The application performs the following steps:

1. Select a directory containing PHP files.
2. Recursively scan all `.php` files.
3. Match file contents against known reverse shell signatures.
4. Extract possible IP addresses and ports.
5. Log detection information.
6. Move malicious files into the quarantine folder.
7. Send a Telegram notification (if configured).

---

## 🚨 Detection Patterns

The tool searches for common reverse shell indicators, including:

- `fsockopen()`
- `stream_socket_client()`
- `exec()`
- `shell_exec()`
- `system()`
- `passthru()`
- `popen()`
- `curl_exec()`
- `base64_decode()`
- `eval(base64_decode())`

These functions are commonly abused by attackers to establish remote shell connections.

---

## 📱 Telegram Notifications

To receive instant alerts, create a `.env` file in the project directory.

```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

Whenever a malicious file is detected, the application sends a notification containing:

- File Name
- File Location
- Extracted IP Address
- Port Number

---

## 📦 Quarantine

Detected malicious PHP files are automatically moved to a dedicated **quarantine** folder to prevent accidental execution.

---

## 📝 Logging

All scan activities are recorded in:

```text
shell_detector.log
```

Logs include:

- Scan start time
- Detection results
- Extracted IP and Port
- Quarantine status
- Telegram notification status
- Errors (if any)

---

## 📌 Applications

- Malware Detection
- Web Server Security
- Cybersecurity Education
- Secure PHP Code Review
- Incident Response
- Digital Forensics
- Threat Hunting
- Security Operations Center (SOC)

---

## 🔮 Future Enhancements

- Machine Learning-based malware detection
- YARA rule integration
- Multi-threaded scanning
- Support for ASP, JSP, and Python web shells
- PDF scan report generation
- Real-time directory monitoring
- VirusTotal API integration
- Email notifications
- Web dashboard
- Docker deployment

---

## ⚠️ Disclaimer

This project is intended **only for educational, research, and defensive cybersecurity purposes**.

Do not use this software for unauthorized access or malicious activities. The author is not responsible for any misuse of this project.

---

## 👩‍💻 Author

**Anusree Dodle**

GitHub: https://github.com/anusreedodle

---

