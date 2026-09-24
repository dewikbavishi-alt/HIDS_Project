import os
import time
import hashlib
import logging
import threading
import queue
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR_DIR = os.path.join(BASE_DIR, "monitored_files")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")
BASELINE_FILE = os.path.join(BASE_DIR, "baseline_hashes.txt")

SUSPICIOUS_PROCESSES = [
    "keylogger.exe",
    "trojan.exe",
    "meterpreter.exe",
    "netcat.exe",
    "nc.exe",
    "mimikatz.exe",
]

SUSPICIOUS_PORTS = [4444, 5555, 6666, 31337]

running = False
observer = None
alert_count = 0
already_alerted_processes = set()
already_alerted_connections = set()
already_alerted_files = set()
ui_queue = queue.Queue()

os.makedirs(MONITOR_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def write_output(message, is_alert=False):
    ui_queue.put((message, is_alert))


def process_ui_queue():
    global alert_count

    while not ui_queue.empty():
        message, is_alert = ui_queue.get()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if is_alert:
            alert_count += 1
            final_message = f"[{timestamp}] [ALERT] {message}"
            logging.warning(message)
            alert_count_label.config(text=f"Alerts Detected: {alert_count}")
        else:
            final_message = f"[{timestamp}] {message}"
            logging.info(message)

        output_box.insert(tk.END, final_message + "\n")
        output_box.see(tk.END)

    root.after(100, process_ui_queue)


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(4096)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except FileNotFoundError:
        return None

    except PermissionError:
        write_output(f"Permission denied while reading file: {file_path}", True)
        return None


def create_baseline():
    with open(BASELINE_FILE, "w") as baseline:
        for root_dir, dirs, files in os.walk(MONITOR_DIR):
            for file_name in files:
                file_path = os.path.join(root_dir, file_name)
                file_hash = calculate_hash(file_path)

                if file_hash:
                    baseline.write(f"{file_path}|{file_hash}\n")

    write_output("Baseline created successfully.")


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
            status = "deleted"
        elif current_hash != old_hash:
            status = f"modified:{current_hash}"
        else:
            # File is back to its baseline state, so allow future alerts
            already_alerted_files.difference_update(
                {key for key in already_alerted_files
                 if key.startswith(file_path + ":")}
            )
            continue

        alert_key = f"{file_path}:{status}"

        if alert_key not in already_alerted_files:
            already_alerted_files.add(alert_key)
            write_output(
                f"Integrity check failed - file {status.split(':')[0]}: {file_path}",
                True
            )


class FileChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            write_output(f"New file created: {event.src_path}", True)

    def on_deleted(self, event):
        if not event.is_directory:
            write_output(f"File deleted: {event.src_path}", True)

    def on_modified(self, event):
        if not event.is_directory:
            write_output(f"File modified: {event.src_path}", True)

    def on_moved(self, event):
        if not event.is_directory:
            write_output(
                f"File moved from {event.src_path} to {event.dest_path}",
                True
            )


def start_file_monitor():
    global observer

    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()

    write_output(f"Real-time file monitoring started for: {MONITOR_DIR}")


def stop_file_monitor():
    global observer

    if observer:
        observer.stop()
        observer.join()
        observer = None
        write_output("Real-time file monitoring stopped.")


def monitor_processes():
    for process in psutil.process_iter(["pid", "name"]):
        try:
            process_name = process.info["name"]

            if not process_name:
                continue

            process_name_lower = process_name.lower()
            pid = process.info["pid"]

            if process_name_lower in SUSPICIOUS_PROCESSES:
                alert_key = f"{process_name_lower}:{pid}"

                if alert_key not in already_alerted_processes:
                    already_alerted_processes.add(alert_key)

                    write_output(
                        f"Suspicious process detected: {process_name} PID: {pid}",
                        True
                    )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def monitor_network():
    try:
        connections = psutil.net_connections(kind="inet")

        for conn in connections:
            if conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

                if remote_port in SUSPICIOUS_PORTS:
                    alert_key = f"{remote_ip}:{remote_port}"

                    if alert_key not in already_alerted_connections:
                        already_alerted_connections.add(alert_key)

                        write_output(
                            f"Suspicious network connection detected: "
                            f"{remote_ip}:{remote_port}",
                            True
                        )

    except psutil.AccessDenied:
        write_output(
            "Access denied while checking network connections. "
            "Try running PowerShell as Administrator.",
            True
        )


def monitoring_loop():
    while running:
        check_file_integrity()
        monitor_processes()
        monitor_network()

        scan_time = datetime.now().strftime("%H:%M:%S")
        root.after(
            0,
            lambda time_value=scan_time: last_scan_label.config(
                text="Last Scan: " + time_value
            )
        )

        time.sleep(10)


def start_monitoring():
    global running

    if running:
        write_output("HIDS is already running.")
        return

    running = True
    status_label.config(text="Status: Running", fg="#1b7f3a")

    write_output("Host-Based Intrusion Detection System Started")
    write_output(f"Monitoring directory: {MONITOR_DIR}")
    write_output(f"Alerts will be stored in: {LOG_FILE}")

    if not os.path.exists(BASELINE_FILE):
        create_baseline()
    else:
        write_output("Existing baseline loaded successfully.")

    start_file_monitor()

    thread = threading.Thread(target=monitoring_loop, daemon=True)
    thread.start()


def stop_monitoring():
    global running

    if not running:
        write_output("HIDS is already stopped.")
        return

    running = False
    status_label.config(text="Status: Stopped", fg="#b3261e")
    stop_file_monitor()
    write_output("HIDS stopped.")


def clear_ui_output():
    global alert_count

    alert_count = 0
    output_box.delete("1.0", tk.END)
    alert_count_label.config(text="Alerts Detected: 0")


def rebuild_baseline():
    already_alerted_files.clear()
    create_baseline()
    write_output("Baseline rebuilt. Current files are now treated as safe.")


def on_close():
    global running

    running = False
    stop_file_monitor()
    root.destroy()


root = tk.Tk()
root.title("Host-Based Intrusion Detection System")
root.geometry("900x620")
root.configure(bg="#f4f6f8")

title_label = tk.Label(
    root,
    text="Host-Based Intrusion Detection System",
    font=("Arial", 20, "bold"),
    bg="#f4f6f8",
    fg="#1f2933"
)
title_label.pack(pady=15)

status_label = tk.Label(
    root,
    text="Status: Stopped",
    font=("Arial", 14, "bold"),
    bg="#f4f6f8",
    fg="#b3261e"
)
status_label.pack()

button_frame = tk.Frame(root, bg="#f4f6f8")
button_frame.pack(pady=15)

tk.Button(
    button_frame,
    text="Start Monitoring",
    width=18,
    bg="#1b7f3a",
    fg="white",
    command=start_monitoring
).grid(row=0, column=0, padx=8)

tk.Button(
    button_frame,
    text="Stop Monitoring",
    width=18,
    bg="#b3261e",
    fg="white",
    command=stop_monitoring
).grid(row=0, column=1, padx=8)

tk.Button(
    button_frame,
    text="Clear UI Output",
    width=18,
    bg="#455a64",
    fg="white",
    command=clear_ui_output
).grid(row=0, column=2, padx=8)

tk.Button(
    button_frame,
    text="Rebuild Baseline",
    width=18,
    bg="#1565c0",
    fg="white",
    command=rebuild_baseline
).grid(row=0, column=3, padx=8)

info_frame = tk.Frame(root, bg="white", bd=1, relief="solid")
info_frame.pack(fill="x", padx=30, pady=10)

alert_count_label = tk.Label(
    info_frame,
    text="Alerts Detected: 0",
    font=("Arial", 12),
    bg="white",
    fg="#1f2933"
)
alert_count_label.grid(row=0, column=0, padx=25, pady=12)

last_scan_label = tk.Label(
    info_frame,
    text="Last Scan: Not started",
    font=("Arial", 12),
    bg="white",
    fg="#1f2933"
)
last_scan_label.grid(row=0, column=1, padx=25, pady=12)

monitor_label = tk.Label(
    info_frame,
    text=f"Monitoring Folder: {MONITOR_DIR}",
    font=("Arial", 12),
    bg="white",
    fg="#1f2933"
)
monitor_label.grid(row=0, column=2, padx=25, pady=12)

output_title = tk.Label(
    root,
    text="HIDS Output and Alert Logs",
    font=("Arial", 14, "bold"),
    bg="#f4f6f8",
    fg="#1f2933"
)
output_title.pack(pady=5)

output_box = scrolledtext.ScrolledText(
    root,
    width=105,
    height=24,
    font=("Consolas", 10),
    bg="#101820",
    fg="#e8f0f2",
    insertbackground="white"
)
output_box.pack(padx=30, pady=10)

root.protocol("WM_DELETE_WINDOW", on_close)

root.after(100, process_ui_queue)

root.mainloop()