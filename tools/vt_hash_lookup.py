#!/usr/bin/env python3
"""vt_hash_lookup.py - Hash every file in a folder and look the hashes up on VirusTotal.

Files are never uploaded; only their MD5 hashes are queried, so this is safe
for sensitive samples. Reads the API key from the VT_API_KEY environment variable.

Usage:
    export VT_API_KEY=...            # Windows: set VT_API_KEY=...
    python vt_hash_lookup.py <directory> [--out vt_report.txt] [--delay 15]

The free VirusTotal API allows 4 lookups per minute; the default delay respects that.
"""
import argparse
import hashlib
import os
import sys
import time

import requests

API = "https://www.virustotal.com/api/v3/files/{}"


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def lookup(md5, key):
    r = requests.get(API.format(md5), headers={"x-apikey": key}, timeout=20)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    attrs = r.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    return {
        "positives": stats.get("malicious", 0),
        "total": total,
        "name": attrs.get("meaningful_name", ""),
        "link": f"https://www.virustotal.com/gui/file/{md5}",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("directory")
    ap.add_argument("--out", default="vt_report.txt")
    ap.add_argument("--delay", type=float, default=15.0)
    a = ap.parse_args()

    key = os.environ.get("VT_API_KEY")
    if not key:
        sys.exit("Set the VT_API_KEY environment variable first.")

    files = sorted((f for f in os.listdir(a.directory) if os.path.isfile(os.path.join(a.directory, f))), key=str.lower)
    with open(a.out, "w") as out:
        for i, name in enumerate(files):
            md5 = md5_of(os.path.join(a.directory, name))
            try:
                res = lookup(md5, key)
            except requests.RequestException as e:
                res, err = None, str(e)
            else:
                err = None
            lines = [f"File: {name}", f"  MD5: {md5}"]
            if err:
                lines.append(f"  Error: {err}")
            elif res is None:
                lines.append("  Not found in VirusTotal")
            else:
                lines += [f"  Detections: {res['positives']} / {res['total']} engines",
                          f"  Known as: {res['name'] or 'n/a'}",
                          f"  Report: {res['link']}"]
            block = "\n".join(lines)
            print(block + "\n")
            out.write(block + "\n" + "-" * 50 + "\n")
            if i < len(files) - 1:
                time.sleep(a.delay)
    print(f"Report written to {a.out}")


if __name__ == "__main__":
    main()
