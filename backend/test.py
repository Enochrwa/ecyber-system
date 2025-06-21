import logging
from scapy.all import sniff
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Interface to sniff on
IFACE = os.getenv("SNIFFER_IFACE", "enp0s8")

def packet_handler(pkt):
    try:
        # Display basic info
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst
            proto = pkt["IP"].proto
            logging.info(f"Captured packet: {src} -> {dst} [proto={proto}]")
        else:
            logging.info(f"Non-IP packet: {pkt.summary()}")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def main():
    logging.info(f"🔍 Starting test sniffer on interface: {IFACE}")
    try:
        sniff(iface=IFACE, prn=packet_handler, store=False)
    except PermissionError:
        logging.error("🚫 Permission denied. Try running with sudo.")
    except Exception as e:
        logging.error(f"Sniffer crashed: {e}")

if __name__ == "__main__":
    main()
