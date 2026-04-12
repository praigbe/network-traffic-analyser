 # Network Traffic Analyser

A Python tool that captures live network traffic, spots suspicious behaviour, and writes a security report. Built as part of my cybersecurity portfolio while working towards a degree apprenticeship in 2027.

---

## Why I built this

I wanted a project that went beyond theory and actually touched real networking concepts — packet capture, protocol detection, port scan logic. The kind of stuff that comes up in SOC analyst and cyber security roles. This felt like the most honest way to show I understand what's happening on a network, not just that I've read about it.

---

## What it does

- Captures live packets (TCP, UDP, ICMP) from your network interface
- Identifies protocols and destination ports in real time
- Flags suspicious activity — port scans and connections to sensitive ports like SSH, RDP, and SMB
- Generates a `report.txt` with a full packet log and any alerts raised

---

## Challenges I ran into

**Scapy needs root privileges** — it wouldn't run at all until I figured out it needs access to raw sockets, which requires sudo. That was my first real lesson in why low-level network tools operate differently to normal Python scripts.

**Sudo broke my virtual environment** — running `sudo python analyser.py` bypassed the venv completely, so none of my installed packages were found. The fix was `sudo venv/bin/python analyser.py` to point it at the right Python binary. Took me a while to work out but I actually understand Linux PATH resolution a lot better now because of it.

**Keeping the report off GitHub** — the generated report contains real IP addresses from my network. Pushing that publicly would be a security risk, so I added `report.txt` to `.gitignore`. Small thing but it's the kind of habit that matters in a real security role.

---

## How to run it

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python analyser.py
```

---

## Skills this shows

- Python scripting and working with third-party libraries
- Networking fundamentals — TCP/IP, ports, packet structure
- Basic intrusion detection logic (the same concepts behind tools like Snort)
- Linux command line and understanding of how environments and permissions work
- Security awareness — knowing what not to expose publicly

---

Built by Presley 
