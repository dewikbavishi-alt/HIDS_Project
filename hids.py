import os
import time
import hashlib
import logging
import psutil
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR_DIR = os.path.join(BASE_DIR, "monitored_files")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")
BASELINE_FILE = os.path.join(BASE_DIR, "baseline_hashes.txt")

SUSPICIOUS_PROCESSES = [
    "keylogger.exe",
    "malware.exe",
    "trojan.exe",
    "meterpreter.exe",
    "nc.exe",
    "netcat.exe",
    "mimikatz.exe",
]

SUSPICIOUS_PORTS = [
    4444,
    5555,
    6666,
    31337
]

# Remember what has already been reported so each event alerts only once
already_alerted = set()

os.makedirs(MONITOR_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def alert(message, key=None):
    if key is not None:
        if key in already_alerted:
            return
        already_alerted.add(key)

    print("[ALERT]", message)
    logging.warning(message)


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None


def create_baseline():
    with open(BASELINE_FILE, "w") as baseline:
        for root, dirs, files in os.walk(MONITOR_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = calculate_hash(file_path)

                if file_hash:
                    baseline.write(f"{file_path}|{file_hash}\n")

    print("Baseline created successfully.")


def load_baseline():
    hashes = {}

    if not os.path.exists(BASELINE_FILE):
        return hashes

    with open(BASELINE_FILE, "r") as baseline:
        for line in baseline:
            line = line.strip()

            if "|" in line:
                file_path, file_hash = line.split("|", 1)
                hashes[file_path] = file_hash

    return hashes


def check_file_integrity():
    old_hashes = load_baseline()

    for file_path, old_hash in old_hashes.items():
        current_hash = calculate_hash(file_path)

        if current_hash is None:
            alert(f"Integrity check failed - file deleted: {file_path}",
                  key=f"{file_path}:deleted")
        elif current_hash != old_hash:
            alert(f"Integrity check failed - file modified: {file_path}",
                  key=f"{file_path}:{current_hash}")


class FileChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            alert(f"New file created: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            alert(f"File deleted: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            alert(f"File modified: {event.src_path}")

    def on_moved(self, event):
        if not event.is_directory:
            alert(f"File moved from {event.src_path} to {event.dest_path}")


def monitor_files():
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()
    return observer


def monitor_processes():
    for process in psutil.process_iter(["pid", "name"]):
        try:
            process_name = (process.info["name"] or "").lower()
            pid = process.info["pid"]

            # Exact match, so e.g. "rsync.exe" is not flagged as "nc.exe"
            if process_name in SUSPICIOUS_PROCESSES:
                alert(
                    f"Suspicious process detected: "
                    f"{process.info['name']} PID: {pid}",
                    key=f"proc:{process_name}:{pid}"
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def monitor_network():
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        alert("Access denied while checking network connections. "
              "Try running as Administrator.", key="net:access-denied")
        return

    for conn in connections:
        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            if remote_port in SUSPICIOUS_PORTS:
                alert(
                    f"Suspicious network connection detected: "
                    f"{remote_ip}:{remote_port}",
                    key=f"net:{remote_ip}:{remote_port}"
                )


def main():
    print("Host-Based Intrusion Detection System Started")
    print("Monitoring directory:", MONITOR_DIR)
    print("Alerts will be stored in:", LOG_FILE)

    if not os.path.exists(BASELINE_FILE):
        create_baseline()

    observer = monitor_files()

    try:
        while True:
            check_file_integrity()
            monitor_processes()
            monitor_network()
            time.sleep(10)

    except KeyboardInterrupt:
        observer.stop()
        print("HIDS stopped.")

    observer.join()


if __name__ == "__main__":
    main()