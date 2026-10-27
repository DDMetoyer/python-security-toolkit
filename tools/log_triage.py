#!/usr/bin/env python3
"""log_triage.py - Summarize malware detections and security events in a syslog file.

Counts antivirus "Worm.<name> FOUND" detections (ClamAV-style) and pulls out
authentication failures and request-flood warnings.

Usage:
    python log_triage.py <logfile> [--events N]
"""
import argparse
import re
from collections import Counter

from prettytable import PrettyTable

WORM_RE = re.compile(r"Worm\.([\w.\-]+)\s+FOUND")
EVENT_MARKERS = ("authentication failure", "requests/sec are too many")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile")
    ap.add_argument("--events", type=int, default=10, help="number of security events to show")
    args = ap.parse_args()

    worms, events = Counter(), []
    with open(args.logfile, encoding="utf-8", errors="ignore") as f:
        for line in f:
            for name in WORM_RE.findall(line):
                worms[name] += 1
            if any(m in line for m in EVENT_MARKERS):
                events.append(line.strip())

    table = PrettyTable(["Worm", "Detections"])
    table.align = "l"
    for name, count in worms.most_common():
        table.add_row([name, count])
    print("=== Malware detections ===")
    print(table)

    print(f"\n=== Security events ({len(events)} total, showing {min(args.events, len(events))}) ===")
    for e in events[: args.events]:
        print(e)


if __name__ == "__main__":
    main()
