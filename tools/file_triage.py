#!/usr/bin/env python3
"""file_triage.py - Hash and fingerprint every file under a directory.

For each file: size, modified/created times, MD5 and SHA-256, and the first
20 bytes of the header in hex (useful for spotting mismatched extensions).
Also reports files that share the same hash (duplicates).

Usage:
    python file_triage.py <directory> [--csv out.csv]
"""
import argparse
import csv
import hashlib
import os
import time
from collections import defaultdict

from prettytable import PrettyTable

HEADER_BYTES = 20
CHUNK = 65536


class FileProcessor:
    """Collects file-system metadata, hashes and header bytes for one file."""

    def __init__(self, path):
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        self.path = os.path.abspath(path)
        st = os.stat(self.path)
        self.size = st.st_size
        self.modified = time.ctime(st.st_mtime)
        self.created = time.ctime(st.st_ctime)
        self.md5, self.sha256 = self._hash()
        self.header_hex = self._header()

    def _hash(self):
        md5, sha = hashlib.md5(), hashlib.sha256()
        with open(self.path, "rb") as f:
            while chunk := f.read(CHUNK):
                md5.update(chunk)
                sha.update(chunk)
        return md5.hexdigest(), sha.hexdigest()

    def _header(self):
        with open(self.path, "rb") as f:
            return f.read(HEADER_BYTES).hex(" ")


def walk(directory):
    for root, _dirs, files in os.walk(directory):
        for name in files:
            yield os.path.join(root, name)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("directory")
    ap.add_argument("--csv", help="also write results to this CSV file")
    args = ap.parse_args()

    results, by_hash = [], defaultdict(list)
    for path in walk(args.directory):
        try:
            fp = FileProcessor(path)
        except (OSError, FileNotFoundError) as e:
            print(f"[skip] {path}: {e}")
            continue
        results.append(fp)
        by_hash[fp.sha256].append(fp.path)

    table = PrettyTable(["File", "Size", "Modified", "MD5", "Header (hex)"])
    table.align = "l"
    for fp in results:
        table.add_row([fp.path, fp.size, fp.modified, fp.md5, fp.header_hex])
    print(table)

    dupes = {h: p for h, p in by_hash.items() if len(p) > 1}
    print(f"\n{len(results)} files hashed, {len(dupes)} duplicate groups")
    for h, paths in dupes.items():
        print(f"  SHA-256 {h[:16]}... -> {', '.join(paths)}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["path", "size", "modified", "created", "md5", "sha256", "header_hex"])
            for fp in results:
                w.writerow([fp.path, fp.size, fp.modified, fp.created, fp.md5, fp.sha256, fp.header_hex])
        print(f"CSV written: {args.csv}")


if __name__ == "__main__":
    main()
