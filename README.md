# Simple Network Intrusion Detection System (NIDS)

This is a **simple Intrusion Detection System** (IDS) written in Python using Scapy. It runs on **Kali Linux** and monitors real-time network traffic for **suspicious behavior**, like port scanning or backdoor access attempts.



---

##  What It Does

This tool monitors your **network interface** (like `eth0`) and watches for:

- **SYN Scans** (common in Nmap and stealth attacks)
- **Access to suspicious ports** (like port `23` for Telnet, or backdoor ports like `4444`, `31337`)

When suspicious activity is detected:
- It prints a warning on your terminal
- It saves the alert to a file called `alerts.log`
- (Optional) It can also send you an **email notification** (if configured)

---

##  Sample Output

When someone tries to scan your machine, this is what you'll see:

```text
[*] 192.168.64.1:60591 -> 192.168.64.128:80 | Proto: 6 | Len: 60
[2025-06-20 07:40:07] [!] Possible SYN scan from 192.168.64.1
[2025-06-20 07:40:07] [!] Suspicious port access from 192.168.64.1 to port 23
