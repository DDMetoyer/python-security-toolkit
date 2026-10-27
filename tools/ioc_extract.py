#!/usr/bin/env python3
"""ioc_extract.py - Carve e-mail addresses, URLs and readable strings out of binary files.

Works on memory dumps, disk images or any binary: the file is streamed in
chunks so large dumps don't need to fit in memory. Results are de-duplicated
and ranked by number of occurrences.

Usage:
    python ioc_extract.py <file> [--emails] [--urls] [--strings] [--min 5 --max 12] [--top 50]
    (with no selector flags, all three are extracted)
"""
import argparse
import re
from collections import Counter

from prettytable import PrettyTable

CHUNK = 1 << 20
OVERLAP = 256  # bytes carried between chunks so matches spanning a boundary aren't lost

EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
URL_RE = re.compile(rb"[a-zA-Z][\w+.-]*://[\w@][\w.:@-]+/?[\w./?=%&\-@$,~+#]*")


def scan(path, patterns):
    counters = {k: Counter() for k in patterns}
    tail = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            data = tail + chunk
            # only count matches that start in the non-overlap region to avoid double counting
            limit = len(data) - OVERLAP if chunk else len(data)
            for key, rx in patterns.items():
                for m in rx.finditer(data):
                    if m.start() < limit:
                        counters[key][m.group().lower()] += 1
            if not chunk:
                break
            tail = data[limit:]
    return counters


def show(title, counter, top):
    t = PrettyTable(["Occurrences", title])
    t.align = "l"
    for value, n in counter.most_common(top):
        t.add_row([n, value.decode("ascii", "ignore")])
    print(f"\n{title.upper()} ({len(counter)} unique)")
    print(t)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file")
    ap.add_argument("--emails", action="store_true")
    ap.add_argument("--urls", action="store_true")
    ap.add_argument("--strings", action="store_true", help="alphabetic words between --min and --max chars")
    ap.add_argument("--min", type=int, default=5)
    ap.add_argument("--max", type=int, default=12)
    ap.add_argument("--top", type=int, default=50, help="rows to display per table")
    a = ap.parse_args()
    if not (a.emails or a.urls or a.strings):
        a.emails = a.urls = a.strings = True

    patterns = {}
    if a.emails:
        patterns["e-mail address"] = EMAIL_RE
    if a.urls:
        patterns["url"] = URL_RE
    if a.strings:
        patterns["string"] = re.compile(rb"(?<![A-Za-z])[A-Za-z]{%d,%d}(?![A-Za-z])" % (a.min, a.max))

    for title, counter in scan(a.file, patterns).items():
        show(title, counter, a.top)


if __name__ == "__main__":
    main()
