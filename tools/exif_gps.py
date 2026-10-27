#!/usr/bin/env python3
"""exif_gps.py - Extract GPS coordinates, timestamps and camera info from JPEG EXIF data.

Processes every .jpg/.jpeg in a directory, prints a table, and writes a CSV
that can be dropped into any mapping tool (e.g. Google My Maps, QGIS).

Usage:
    python exif_gps.py <directory> [--csv image_gps_data.csv]
"""
import argparse
import csv
import math
import os

from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS
from prettytable import PrettyTable


def extract_exif(path):
    """Return (gps_dict, [timestamp, make, model]) or (None, None)."""
    try:
        exif = Image.open(path)._getexif()
    except Exception:
        return None, None
    if not exif:
        return None, None

    timestamp = make = model = "NA"
    gps = {}
    for tag, value in exif.items():
        name = TAGS.get(tag, tag)
        if name == "DateTimeOriginal":
            timestamp = str(value).strip()
        elif name == "Make":
            make = str(value).strip()
        elif name == "Model":
            model = str(value).strip()
        elif name == "GPSInfo":
            for gtag in value:
                gps[GPSTAGS.get(gtag, gtag)] = value[gtag]
    return gps, [timestamp, make, model]


def to_decimal(dms, ref):
    deg, minutes, seconds = (float(x) for x in dms)
    dec = deg + minutes / 60.0 + seconds / 3600.0
    return -dec if ref in ("S", "W") else dec


def lat_lon(gps):
    try:
        lat = to_decimal(gps["GPSLatitude"], gps["GPSLatitudeRef"])
        lon = to_decimal(gps["GPSLongitude"], gps["GPSLongitudeRef"])
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None
    if math.isnan(lat) or math.isnan(lon):
        return None  # tag present but empty (0/0 rationals)
    return lat, lon


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("directory")
    ap.add_argument("--csv", default="image_gps_data.csv")
    args = ap.parse_args()

    table = PrettyTable(["File", "Latitude", "Longitude", "Timestamp", "Make", "Model"])
    rows = []
    for name in sorted(os.listdir(args.directory)):
        if not name.lower().endswith((".jpg", ".jpeg")):
            continue
        gps, info = extract_exif(os.path.join(args.directory, name))
        ts, make, model = info or ("NA", "NA", "NA")
        coords = lat_lon(gps) if gps else None
        if coords:
            table.add_row([name, f"{coords[0]:.6f}", f"{coords[1]:.6f}", ts, make, model])
            rows.append([name, coords[0], coords[1], ts, make, model])
        else:
            table.add_row([name, "No GPS", "No GPS", ts, make, model])
    print(table)

    with open(args.csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file", "latitude", "longitude", "timestamp", "make", "model"])
        w.writerows(rows)
    print(f"\n{len(rows)} geotagged images written to {args.csv}")


if __name__ == "__main__":
    main()
