import json
import os
import signal
import datetime
import time
from collections import defaultdict
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP
from scapy.layers.dns import DNSQR

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Load rules
def load_rules():
    with open("rules.json") as f:
        return json.load(f)

rules = load_rules()

# Scan tracker
scan_tracker = defaultdict(lambda: {"ports": set(), "time": time.time()})
auto_blocked = set()

# Rule checks
def is_blocked_ip(ip):
    return ip.strip() in rules.get("block_ip", []) and ip not in rules.get("whitelist_ip", [])

def is_blocked_port(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP].dport in rules.get("block_port", [])
    if pkt.haslayer(UDP):
        return pkt[UDP].dport in rules.get("block_port", [])
    return False

def is_blocked_domain(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode().strip('.')
        for domain in rules.get("block_domains", []):
            if domain in qname:
                return True
    return False

# Logger
def log_action(action, pkt):
    try:
        with open("logs/firewall.log", "a") as f:
            log_line = f"[{datetime.datetime.now()}] {action}: {pkt.src} → {pkt.dst}\n"
            f.write(log_line)
            f.flush()
    except Exception as e:
        print(f"[!] Log error: {e}")

# Main firewall logic
def process_packet(packet):
    pkt = IP(packet.get_payload())
    src_ip = pkt.src

    # DNS blocking
    if is_blocked_domain(pkt):
        print(f"[DNS BLOCK] {pkt.src} tried to access blocked domain.")
        log_action("DNS BLOCK", pkt)
        packet.drop()
        return

    # Port scan detection
    if pkt.haslayer(TCP):
        now = time.time()
        scan = scan_tracker[src_ip]

        if now - scan["time"] < 5:
            scan["ports"].add(pkt[TCP].dport)
            if len(scan["ports"]) > 5:
                if src_ip not in auto_blocked:
                    print(f"[ALERT] Port scan detected from {src_ip}")
                    rules["block_ip"].append(src_ip)
                    auto_blocked.add(src_ip)
                    log_action("AUTO-BLOCKED (Scan)", pkt)
        else:
            scan_tracker[src_ip] = {"ports": {pkt[TCP].dport}, "time": now}

    # Rule-based blocking
    if is_blocked_ip(pkt.dst) or is_blocked_port(pkt):
        print(f"[BLOCKED] {pkt.src} → {pkt.dst}")
        log_action("BLOCKED", pkt)
        packet.drop()
    else:
        log_action("ALLOWED", pkt)
        packet.accept()

# Cleanup on exit
def stop_firewall():
    os.system("iptables -F")
    print("[*] iptables rules cleared. Firewall stopped.")

signal.signal(signal.SIGINT, lambda s, f: stop_firewall() or exit(0))

# Start queue
nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)

print("[*] Firewall is running. Press CTRL+C to stop.")
nfqueue.run()
