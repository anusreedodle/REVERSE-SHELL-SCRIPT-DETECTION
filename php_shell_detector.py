# php_shell_detector.py
import os
import re
import shutil
import logging
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from dotenv import load_dotenv
import requests
import sys

# Load environment
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

LOG_FILE = "shell_detector.log"
QUARANTINE_DIRNAME = "quarantine"

def setup_logging():
    # Log to file and console
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )

def extract_ip_and_port(content):
    """Extracts IP and port from the file content (best-effort)."""
    ip_pattern = r'((?:\d{1,3}\.){3}\d{1,3})'
    port_pattern = r'(?<=[:,(])\d{2,5}(?=[,);])'

    ip_match = re.search(ip_pattern, content)
    port_match = re.search(port_pattern, content)

    ip = ip_match.group(0) if ip_match else "Unknown"
    port = port_match.group(0) if port_match else "Unknown"

    return ip, port

def send_telegram_alert(file_path, ip, port):
    """Send a short Telegram message (best-effort)."""
    if not all([TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID]):
        logging.error("Telegram credentials are missing. Check your .env file.")
        return False

    message = f"⚠ Alert: Reverse Shell Detected\nFile: {file_path}\nIP: {ip}\nPort: {port}"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        r = requests.post(url, data=data, timeout=10)
        if r.status_code == 200:
            logging.info(f"Telegram alert sent for {file_path} (IP: {ip}, Port: {port})")
            return True
        else:
            logging.error(f"Failed to send Telegram alert: {r.status_code} {r.text}")
            return False
    except Exception as e:
        logging.error(f"Error sending Telegram alert: {e}")
        return False

def detect_reverse_shell(file_path):
    """Scans a PHP file for known reverse shell patterns. Returns tuple(found, content)."""
    patterns = [
        r'fsockopen\s*\(',
        r'stream_socket_client\s*\(',
        r'exec\s*\(',
        r'shell_exec\s*\(',
        r'system\s*\(',
        r'passthru\s*\(',
        r'popen\s*\(',
        r'curl_exec\s*\(',
        r'base64_decode\s*\(',
        r'eval\s*\(.*base64_decode'
    ]

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    ip, port = extract_ip_and_port(content)
                    logging.warning(f"Potential reverse shell detected in: {file_path}, IP: {ip}, Port: {port}")
                    return True, content
    except Exception as e:
        logging.error(f"Error scanning {file_path}: {e}")
    return False, None

def quarantine_file(file_path, base_scan_dir):
    """Move the file to a quarantine folder inside the scan directory (keeps original name)."""
    quarantine_dir = os.path.join(base_scan_dir, QUARANTINE_DIRNAME)
    os.makedirs(quarantine_dir, exist_ok=True)
    dest = os.path.join(quarantine_dir, os.path.basename(file_path))
    try:
        shutil.move(file_path, dest)
        logging.info(f"Moved {file_path} to {dest}.")
        return dest
    except Exception as e:
        logging.error(f"Failed to move {file_path} to quarantine: {e}")
        return None

def scan_directory(directory, gui_notify_callback=None):
    """Scan directory for .php files and handle detections."""
    logging.info(f"Scanning directory: {directory}")
    for root, _, files in os.walk(directory):
        for fname in files:
            if fname.lower().endswith(".php"):
                fp = os.path.join(root, fname)
                found, content = detect_reverse_shell(fp)
                if found:
                    ip, port = extract_ip_and_port(content or "")
                    # Send Telegram before moving (best-effort)
                    send_telegram_alert(fp, ip, port)
                    # Quarantine and inform UI
                    quarantined = quarantine_file(fp, directory)
                    if gui_notify_callback:
                        gui_notify_callback(quarantined or fp, ip, port, content)
    logging.info(f"Scan of {directory} completed.")

def continuous_scan(directory, interval_seconds, gui_notify_callback=None):
    """Continuously scan the folder every interval_seconds."""
    try:
        while True:
            scan_directory(directory, gui_notify_callback=gui_notify_callback)
            time.sleep(interval_seconds)
    except Exception as e:
        logging.error(f"Continuous scan error: {e}")

# ---------------- GUI stuff ----------------
class DetectorGUI:
    def __init__(self, root):
        self.root = root
        root.title("PHP Shell Detector")
        root.geometry("800x500")

        self.directory = None
        self.scan_thread = None

        tk.Label(root, text="Select a directory to monitor for reverse shells").pack(pady=6)
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=4)
        tk.Button(btn_frame, text="Select Directory", command=self.select_directory).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="Start Monitoring", command=self.start_monitoring_button).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="Stop Monitoring", command=self.stop_monitoring_button).pack(side=tk.LEFT, padx=6)

        self.listbox = tk.Listbox(root, width=120, height=15)
        self.listbox.pack(padx=10, pady=8, fill=tk.BOTH, expand=False)
        self.listbox.bind("<Double-Button-1>", self.on_item_double_click)

        tk.Label(root, text="Log (recent):").pack(pady=(10,0))
        self.log_area = scrolledtext.ScrolledText(root, height=10)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        self.refresh_log_button = tk.Button(root, text="Refresh Log", command=self.refresh_log)
        self.refresh_log_button.pack(pady=4)

        # monitor control
        self._stop_event = threading.Event()

    def select_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory = directory
            self.listbox.insert(tk.END, f"Selected directory: {directory}")

    def start_monitoring_button(self):
        if not self.directory:
            messagebox.showerror("Error", "Please select a directory first.")
            return
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Info", "Monitoring already running.")
            return

        self._stop_event.clear()
        self.scan_thread = threading.Thread(target=self._background_scan, daemon=True)
        self.scan_thread.start()
        self.listbox.insert(tk.END, f"Monitoring started for {self.directory}")
        logging.info(f"Monitoring started for {self.directory}")

    def stop_monitoring_button(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self._stop_event.set()
            self.scan_thread.join(timeout=2)
            self.listbox.insert(tk.END, "Monitoring stopped.")
            logging.info("Monitoring stopped.")
        else:
            self.listbox.insert(tk.END, "No active monitoring thread.")

    def _background_scan(self):
        interval = 60  # seconds
        while not self._stop_event.is_set():
            scan_directory(self.directory, gui_notify_callback=self.gui_notify)
            # wait with early exit
            for _ in range(int(interval/1)):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def gui_notify(self, quarantined_path, ip, port, original_content):
        """Called when a detection occurs; update GUI listbox and log area."""
        text = f"DETECTED -> {quarantined_path} | IP: {ip} | Port: {port}"
        # push to listbox (on main thread)
        self.root.after(0, lambda: self.listbox.insert(tk.END, text))
        # also append some content snippet to the log area
        snippet = (original_content or "")[:1000]  # first 1000 chars
        self.root.after(0, lambda: self.log_area.insert(tk.END, f"\n{time.ctime()} - {text}\n{snippet}\n\n"))

    def on_item_double_click(self, event):
        """When user double-clicks a listbox item, open quarantined file content if possible."""
        sel = self.listbox.curselection()
        if not sel:
            return
        entry = self.listbox.get(sel[0])
        # extract path between 'DETECTED -> ' and ' | IP:' if present
        if "DETECTED -> " in entry:
            try:
                path = entry.split("DETECTED -> ")[1].split(" | IP:")[0].strip()
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    # show content in popup
                    self.show_file_content(path, content)
                else:
                    messagebox.showinfo("File not found", f"Quarantined file not found: {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file: {e}")

    def show_file_content(self, path, content):
        win = tk.Toplevel(self.root)
        win.title(f"Quarantined file: {os.path.basename(path)}")
        txt = scrolledtext.ScrolledText(win, wrap=tk.NONE, width=100, height=30)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, content)
        txt.configure(state=tk.DISABLED)

    def refresh_log(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()[-20000:]  # last chunk
            self.log_area.delete('1.0', tk.END)
            self.log_area.insert(tk.END, data)
        else:
            self.log_area.delete('1.0', tk.END)
            self.log_area.insert(tk.END, "No log file yet.")

# ----------------- main -----------------
def main():
    setup_logging()

    # If directory arg provided, run headless
    if len(sys.argv) > 1:
        dir_to_watch = sys.argv[1]
        logging.info(f"Headless mode. Watching: {dir_to_watch}")
        try:
            continuous_scan(dir_to_watch, interval_seconds=60, gui_notify_callback=None)
        except KeyboardInterrupt:
            logging.info("Stopped by user (KeyboardInterrupt).")
        return

    # GUI mode
    root = tk.Tk()
    gui = DetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
