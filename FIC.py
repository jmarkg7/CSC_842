import os
import hashlib
import json
import argparse
import subprocess
from datetime import datetime

BASELINE_FILE = "integrity_baseline.json"


def hash_file(path):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error hashing {path}: {e}")
        return None


def list_ads(path):
    """Detect Alternate Data Streams using 'dir /r' (Windows only)."""
    ads = []
    if os.name != 'nt':
        return ads  # ADS only exists on NTFS (Windows)

    try:
        result = subprocess.check_output(['cmd', '/c', f'dir /r "{path}"'], stderr=subprocess.DEVNULL, text=True)
        for line in result.splitlines():
            if ':' in line and not line.strip().startswith('Directory of'):
                parts = line.strip().split()
                for part in parts:
                    if ':' in part and '::$DATA' in part:
                        stream = part.split(':')[1]
                        if stream:
                            ads.append(stream)
    except Exception as e:
        print(f"Error checking ADS for {path}: {e}")
    return ads


def build_baseline(directory):
    """Walk through a directory and record hash and ADS data."""
    file_data = {}
    for root, _, files in os.walk(directory):
        for name in files:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, directory)
            file_hash = hash_file(full_path)
            ads = list_ads(full_path)
            if file_hash:
                file_data[rel_path] = {
                    "hash": file_hash,
                    "ads": ads,
                }
    return file_data


def save_baseline(data):
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=2)


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return {}
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def compare_baseline(new_data, old_data):
    changes = {"modified": [], "new": [], "deleted": [], "ads_changed": []}
    old_files = set(old_data.keys())
    new_files = set(new_data.keys())

    for path in new_files:
        if path not in old_data:
            changes["new"].append(path)
        elif new_data[path]["hash"] != old_data[path]["hash"]:
            changes["modified"].append(path)
        elif set(new_data[path].get("ads", [])) != set(old_data[path].get("ads", [])):
            changes["ads_changed"].append(path)

    for path in old_files - new_files:
        changes["deleted"].append(path)

    return changes


def print_report(changes):
    print("\nIntegrity Check Report:")
    for key, items in changes.items():
        if items:
            print(f"\n{key.upper()} FILES:")
            for item in items:
                print(f" - {item}")
    print("\nCheck complete.")


def main():
    parser = argparse.ArgumentParser(description="File Integrity Checker with ADS Detection")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--init", action="store_true", help="Create new baseline")
    args = parser.parse_args()

    print(f"[{datetime.now()}] Scanning directory: {args.directory}")
    new_data = build_baseline(args.directory)

    if args.init:
        save_baseline(new_data)
        print(f"Baseline saved to {BASELINE_FILE}")
    else:
        old_data = load_baseline()
        changes = compare_baseline(new_data, old_data)
        print_report(changes)


if __name__ == "__main__":
    main()
