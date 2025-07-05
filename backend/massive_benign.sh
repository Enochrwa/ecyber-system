#!/bin/bash

META="192.168.56.106"
KALI="192.168.56.101"

echo "[*] Make sure these tools are installed: ab, iperf3, sshpass, wget, ping, dig, curl."

# Create download folder if needed
mkdir -p /tmp/benign_downloads

# 1) HTTP hammering with ApacheBench (ab)
ab -n 50000 -c 100 http://$META/ &

# 2) HTTP hammering with curl in a tight loop
(
  while true; do
    curl -s http://$META/ > /dev/null
    curl -s http://$META/index.html > /dev/null
  done
) &

# 3) Continuous wget downloads (files and index)
(
  while true; do
    wget -q -O /tmp/benign_downloads/page.html http://$META/
    wget -q -O /tmp/benign_downloads/bigfile http://speedtest.tele2.net/10MB.zip
  done
) &

# 4) iperf3 high bandwidth TCP stream
iperf3 -c $META -P 10 -t 180 &

# 5) Continuous SSH connections (short-lived)
(
  while true; do
    sshpass -p "msfadmin" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 msfadmin@$META "uptime" >/dev/null
  done
) &

# 6) Continuous pings
ping -f -c 100000 $META >/dev/null &

# 7) Continuous DNS lookups
(
  while true; do
    dig +short google.com >/dev/null
    dig +short github.com >/dev/null
    dig +short example.com >/dev/null
  done
) &

# 8) Additional ApacheBench run on Kali (if web server running there)
ab -n 30000 -c 50 http://$KALI/ &

# 9) Another iperf3 stream to Kali
iperf3 -c $KALI -P 5 -t 180 &

# 10) Massive parallel curl
(
  for i in {1..20}; do
    (
      while true; do
        curl -s http://$META/ > /dev/null
      done
    ) &
  done
) &

echo "[*] Massive benign traffic is now running."
echo "[*] Collect flows as long as you need (CTRL+C to stop)."

# Keep script alive
wait
