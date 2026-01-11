# Interactive ARP Network Scanner

⚠️ **Use only on networks you own or have explicit permission to scan.**

An interactive, menu-driven ARP scanner written in Python.  
It discovers live hosts on a local network using ARP requests and optionally resolves hostnames.

---

## Features
- CIDR-based network scanning
- Fast batch ARP requests
- Concurrent hostname resolution
- Progress bars (via tqdm)
- Export results to JSON or CSV
- Interactive CLI menu

---

## Requirements
- Python 3.8+
- Root/Administrator privileges (required for ARP packets)

---

## Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/yourusername/interactive-arp-scanner.git
cd interactive-arp-scanner
