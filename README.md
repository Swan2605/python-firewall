# python-firewall
CLI-based advanced firewall using Python, NetfilterQueue, and Scapy

# 🔥 Advanced Python Firewall (Kali Linux CLI-Based)

## 📌 Project Description
This is a Python-based packet-filtering firewall built using `scapy`, `netfilterqueue`, and `iptables` on Kali Linux. It inspects real-time traffic and dynamically blocks malicious activities based on IPs, ports, DNS queries, and scan behavior.

---

## 🛠️ Features Implemented
| Feature                     | Status   |
|----------------------------|----------|
| 🔒 IP Address Blocking      | ✅ Active |
| 🌐 Port-Based Blocking      | ✅ Active |
| 📛 Domain Name Blocking     | ✅ Active |
| 🚨 Port Scan Detection      | ✅ Active |
| 📄 Logging to Log File      | ✅ Active |

---

## 🧱 Folder Structure

firewall.py # Main script
rules.json # Configurable rules (IP, ports, domains)
logs/firewall.log # Logged actions


---

## 📄 rules.json Example
```json
{
  "block_ip": ["192.168.1.100"],
  "block_port": [80],
  "whitelist_ip": ["8.8.8.8"],
  "block_domains": ["facebook.com"]
}
```
🧪 How to Test
Test	Command
Ping Blocked IP	ping 192.168.1.100
Port Block Test	curl http://example.com
DNS Block Test	nslookup facebook.com
Port Scan Test	nmap -p 1-1000 127.0.0.1
View Logs	cat logs/firewall.log
