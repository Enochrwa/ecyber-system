#!/usr/bin/env python3
import subprocess
import random
import time
import threading

# Targets
TARGETS = ["192.168.56.102", "192.168.56.101"]

# Random port ranges
PORT_RANGES = [
    "1-1000",
    "1001-5000",
    "5001-10000",
    "10000-20000",
    "20000-40000",
    "40000-65535",
]

# Base scan template
def build_scan(target, ports):
    return [
        "nmap",
        "-sS",
        "-Pn",           # No host discovery (scan even if no ping)
        f"-p{ports}",
        "--min-rate", "1000",  # Min packets per sec
        "-T5",          # Insane timing
        target
    ]

# Worker thread to run continuous scans
def scan_worker():
    while True:
        target = random.choice(TARGETS)
        ports = random.choice(PORT_RANGES)
        scan = build_scan(target, ports)
        print(f"[*] Running: {' '.join(scan)}")
        subprocess.run(scan)

if __name__ == "__main__":
    try:
        # Launch multiple threads for parallel scanning
        num_threads = 3
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=scan_worker, daemon=True)
            t.start()
            threads.append(t)

        # Keep main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("[*] Stopping fast port scans.")
