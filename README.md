# Interactive ARP Network Scanner

⚠️ **Legal & Ethical Notice**  
This tool is intended **only for educational purposes and authorized networks**.  
Scanning networks without permission may be illegal in your country.

---

## 📌 Overview

An **interactive, menu-driven ARP network scanner** written in Python.  
It discovers live hosts on a local network using ARP requests and optionally resolves hostnames.

This project demonstrates:
- Computer networking fundamentals (ARP, CIDR)
- Concurrency using ThreadPoolExecutor
- Practical cybersecurity tooling with Scapy
- Clean CLI-based user interaction

---

## ✨ Features

- CIDR-based network scanning (e.g. `192.168.1.0/24`)
- Fast batch ARP scanning
- Concurrent hostname resolution
- Optional progress bars (`tqdm`)
- Interactive menu interface
- Export results to **JSON** or **CSV**
- Multiple scans in a single session

---

## 🧰 Requirements

- **Python 3.8 or higher**
- **Administrator / Root privileges** (required for ARP packets)
- Supported OS:
  - Linux
  - Windows

---

## 📦 Dependencies

External Python packages used:
- `scapy`
- `tqdm` (optional but recommended)

All other modules are part of Python’s standard library.

---

## 🚀 Installation & Usage

---

## 🐧 Linux Installation

### 1️⃣ FULL INSTALLATION 
```bash
git clone https://github.com/shaikhanzaar63-sudo/interactive-arp-scanner
cd interactive-arp-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo python interactive_arp_tool.py
