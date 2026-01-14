#!/usr/bin/env python3
"""
interactive_arp_tool.py

Interactive, menu-driven ARP network scanner. Use only on authorized networks.

Features:
 - Prompt-driven input for target CIDR and options
 - Batch ARP scanning (fast)
 - Concurrent hostname resolution
 - Progress bars (if tqdm installed)
 - View results in-console, save to JSON/CSV
 - Run multiple scans in one session
"""

import os
import sys
import json
import subprocess
import csv
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Iterable

# Optional dependencies
try:
    import scapy.all as scapy
except Exception as e:
    scapy = None

try:
    from tqdm import tqdm
except Exception:
    def tqdm(it, **kwargs):
        return it

def check_root():
    if os.name == "posix":
        try:
            if os.geteuid() != 0:
                print("WARNING: This script typically requires root privileges to send raw ARP packets. Run with sudo/root.")
        except Exception:
            pass

def chunk_iterable(data: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(data), size):
        yield data[i:i + size]

def arp_scan_batch(ips: List[str], timeout: float = 2.0, retry: int = 0) -> List[Dict]:
    if scapy is None:
        raise RuntimeError("scapy is not available. Install scapy and run with privileges.")
    if not ips:
        return []
    pdst = ",".join(ips)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = scapy.ARP(pdst=pdst)
    packet = ether / arp
    answered = []
    for attempt in range(retry + 1):
        ans, _ = scapy.srp(packet, timeout=timeout, verbose=False)
        if ans:
            answered = ans
            break
    results = []
    for sent, received in answered:
        results.append({"IP": received.psrc, "MAC": received.hwsrc})
    return results

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def scan_network(cidr: str, timeout: float = 2.0, batch_size: int = 64, workers: int = 32, retry: int = 0, show_progress: bool = True) -> List[Dict]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if not hosts:
        return []
    results = []
    batches = list(chunk_iterable(hosts, batch_size))
    batch_iter = tqdm(batches, desc="ARP batches", unit="batch") if show_progress else batches
    for batch in batch_iter:
        batch_results = arp_scan_batch(batch, timeout=timeout, retry=retry)
        results.extend(batch_results)
    ips_to_resolve = [r["IP"] for r in results]
    hostname_map = {}
    if ips_to_resolve:
        with ThreadPoolExecutor(max_workers=workers) as exe:
            futures = {exe.submit(resolve_hostname, ip): ip for ip in ips_to_resolve}
            resolve_iter = tqdm(as_completed(futures), total=len(futures), desc="Resolving hostnames", unit="host") if show_progress else as_completed(futures)
            for fut in resolve_iter:
                ip = futures[fut]
                try:
                    hostname_map[ip] = fut.result()
                except Exception:
                    hostname_map[ip] = "Unknown"
    # If ARP found hosts, return them
    if results:
        final = [
            {
                "IP": r["IP"],
                "MAC": r["MAC"],
                "Hostname": hostname_map.get(r["IP"], "Unknown")
            }
            for r in results
        ]
        return final

    # ---- FALLBACK MODE (ARP BLOCKED) ----
    print("[!] ARP scan returned 0 hosts. Falling back to ICMP/TCP scan...")

    fallback_results = []

    for ip in tqdm(hosts, desc="ICMP/TCP scan", unit="host") if show_progress else hosts:
        if icmp_ping(ip) or tcp_ping(ip):
            fallback_results.append({
                "IP": ip,
                "MAC": "Unknown",
                "Hostname": resolve_hostname(ip)
            })

    return fallback_results


def print_result(clients: List[Dict]):
    if not clients:
        print("No hosts discovered.")
        return
    print(f"{'IP':<18}{'MAC':<20}{'Hostname'}")
    print("-" * 70)
    for c in clients:
        print(f"{c['IP']:<18}{c['MAC']:<20}{c['Hostname']}")

def save_json(clients: List[Dict], path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(clients, f, indent=2)
    print(f"[+] Saved JSON to {path}")

def save_csv(clients: List[Dict], path: str):
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["IP", "MAC", "Hostname"])
        writer.writeheader()
        writer.writerows(clients)
    print(f"[+] Saved CSV to {path}")

def input_cidr(prompt: str = "Enter target network (CIDR), e.g. 192.168.1.0/24: ") -> str:
    while True:
        s = input(prompt).strip()
        try:
            # ip_network validates CIDR
            _ = ipaddress.ip_network(s, strict=False)
            return s
        except Exception:
            print("Invalid CIDR. Try again.")

def input_int(prompt: str, default: int) -> int:
    while True:
        s = input(f"{prompt} [{default}]: ").strip()
        if s == "":
            return default
        try:
            v = int(s)
            if v < 0:
                print("Enter a non-negative integer.")
                continue
            return v
        except ValueError:
            print("Invalid integer. Try again.")

def icmp_ping(ip: str, timeout: int = 1) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def tcp_ping(ip: str, ports=(80, 443, 22), timeout: float = 0.5) -> bool:
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            pass
    return False


def input_float(prompt: str, default: float) -> float:
    while True:
        s = input(f"{prompt} [{default}]: ").strip()
        if s == "":
            return default
        try:
            v = float(s)
            if v <= 0:
                print("Enter a positive number.")
                continue
            return v
        except ValueError:
            print("Invalid number. Try again.")

def main_menu():
    state = {
        "cidr": None,
        "timeout": 2.0,
        "batch_size": 64,
        "workers": 32,
        "retry": 0,
        "show_progress": True,
        "last_results": []
    }
    check_root()
    if scapy is None:
        print("WARNING: scapy not found. Install scapy to enable scanning (pip install scapy).")
    while True:
        print("\n--- Interactive ARP Scanner ---")
        print("1) Set target CIDR (current: {})".format(state["cidr"] or "Not set"))
        print("2) Set options (timeout, batch size, workers, retry)")
        print("3) Run scan")
        print("4) View last results")
        print("5) Save last results to JSON/CSV")
        print("6) Clear last results")
        print("7) Exit")
        choice = input("Select an option [1-7]: ").strip()
        if choice == "1":
            state["cidr"] = input_cidr()
        elif choice == "2":
            state["timeout"] = input_float("ARP timeout (seconds)", state["timeout"])
            state["batch_size"] = input_int("Batch size (IPs per ARP packet)", state["batch_size"])
            state["workers"] = input_int("Hostname resolver workers", state["workers"])
            state["retry"] = input_int("ARP retry attempts per batch", state["retry"])
            sp = input("Show progress bars? (Y/n) [{}]: ".format("Y" if state["show_progress"] else "n")).strip().lower()
            if sp in ("n", "no"):
                state["show_progress"] = False
            else:
                state["show_progress"] = True
        elif choice == "3":
            if not state["cidr"]:
                print("Please set CIDR first (option 1).")
                continue
            print(f"Starting scan of {state['cidr']} (timeout={state['timeout']}, batch={state['batch_size']}, workers={state['workers']}, retry={state['retry']})")
            try:
                clients = scan_network(
                    state["cidr"],
                    timeout=state["timeout"],
                    batch_size=state["batch_size"],
                    workers=state["workers"],
                    retry=state["retry"],
                    show_progress=state["show_progress"]
                )
                state["last_results"] = clients
                print(f"[+] Scan complete. {len(clients)} hosts discovered.")
            except KeyboardInterrupt:
                print("\nScan interrupted by user.")
            except Exception as e:
                print(f"ERROR during scan: {e}")
        elif choice == "4":
            print_result(state["last_results"])
        elif choice == "5":
            if not state["last_results"]:
                print("No results to save.")
                continue
            path_json = input("Enter JSON output path (leave blank to skip): ").strip()
            if path_json:
                try:
                    save_json(state["last_results"], path_json)
                except Exception as e:
                    print(f"Failed to save JSON: {e}")
            path_csv = input("Enter CSV output path (leave blank to skip): ").strip()
            if path_csv:
                try:
                    save_csv(state["last_results"], path_csv)
                except Exception as e:
                    print(f"Failed to save CSV: {e}")
        elif choice == "6":
            state["last_results"] = []
            print("Cleared last results.")
        elif choice == "7":
            print("Exiting.")
            break
        else:
            print("Invalid selection. Choose 1-7.")

if __name__ == "__main__":
    main_menu()

