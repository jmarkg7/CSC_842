# pcap_compare.py

import os
import sys
import json
import pyshark

TSHARK_PATH = r"D:\DSU\INFA 754 Network Monitoring\Wireshark\tshark.exe"

def extract_flows(pcap_file):
    """Extract unique flows from a PCAP file."""
    flows = set()
    try:
        cap = pyshark.FileCapture(
            pcap_file,
            only_summaries=True,
            tshark_path=TSHARK_PATH
        )
        for pkt in cap:
            try:
                proto = pkt.protocol
                src = pkt.source
                dst = pkt.destination
                info = pkt.info.lower()

                dst_port = None
                if "->" in info:
                    parts = info.split("->")
                    if len(parts) > 1:
                        dst_port = parts[1].split()[0]

                flow = (src, dst, dst_port, proto)
                flows.add(flow)
            except Exception:
                continue
        cap.close()
    except Exception as e:
        print(f" Error reading {pcap_file}: {e}")
        sys.exit(1)
    return flows

def load_whitelist(path):
    if os.path.exists(path):
        with open(path, 'r') as f:
            return set(tuple(entry) for entry in json.load(f))
    return set()

def save_whitelist(path, whitelist):
    with open(path, 'w') as f:
        json.dump([list(entry) for entry in whitelist], f, indent=2)

def compare_pcaps(baseline, target, whitelist_path='whitelist.json'):
    print(f" Baseline: {baseline}")
    print(f" Target  : {target}")

    base_flows = extract_flows(baseline)
    target_flows = extract_flows(target)
    whitelist = load_whitelist(whitelist_path)

    new_flows = target_flows - base_flows - whitelist

    if new_flows:
        print("\n New or unexpected flows found:")
        for flow in sorted(new_flows):
            print(f"  [+] {flow}")
    else:
        print("\n No new or suspicious flows detected.")

    if new_flows:
        update = input("\n Add these flows to whitelist? (y/n): ").strip().lower()
        if update == 'y':
            updated_whitelist = whitelist.union(new_flows)
            save_whitelist(whitelist_path, updated_whitelist)
            print(" Whitelist updated.")
        else:
            print(" Whitelist not updated.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python pcap_compare.py <baseline.pcap> <target.pcap> [whitelist.json]")
        sys.exit(1)

    baseline_pcap = sys.argv[1]
    target_pcap = sys.argv[2]
    whitelist_file = sys.argv[3] if len(sys.argv) > 3 else 'whitelist.json'

    compare_pcaps(baseline_pcap, target_pcap, whitelist_file)
