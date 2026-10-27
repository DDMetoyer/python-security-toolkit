#!/usr/bin/env python3
"""lsb_stego.py - Hide and recover short coded messages in the least-significant bits of an image.

A codebook maps 3-bit codes to messages (e.g. "101 Meet at the safe house").
Each code is stored in one pixel: one bit in the LSB of each of R, G and B,
so the visual change is at most 1/255 per channel. The number of embedded
codes is stored in the first pixel row as a 3-pixel header.

Use a lossless format (BMP/PNG); JPEG compression destroys LSB data.

Usage:
    python lsb_stego.py embed cover.bmp out.bmp --codebook CodeBook.txt --codes 101 011 110
    python lsb_stego.py extract out.bmp --codebook CodeBook.txt
"""
import argparse
import sys

from PIL import Image

HEADER_PIXELS = 3  # 9 bits -> up to 511 codes


def load_codebook(path):
    book = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2 and len(parts[0]) == 3 and set(parts[0]) <= {"0", "1"}:
                book[parts[0]] = parts[1]
    if not book:
        sys.exit("Codebook is empty or malformed (expected lines like '101 message').")
    return book


def coords(i, width):
    return i % width, i // width


def write_bits(pix, i, width, bits):
    x, y = coords(i, width)
    r, g, b = pix[x, y][:3]
    pix[x, y] = ((r & ~1) | bits[0], (g & ~1) | bits[1], (b & ~1) | bits[2])


def read_bits(pix, i, width):
    x, y = coords(i, width)
    return [c & 1 for c in pix[x, y][:3]]


def embed(a):
    book = load_codebook(a.codebook)
    bad = [c for c in a.codes if c not in book]
    if bad:
        sys.exit(f"Codes not in codebook: {', '.join(bad)}")
    img = Image.open(a.cover).convert("RGB")
    if len(a.codes) + HEADER_PIXELS > img.width * img.height:
        sys.exit("Image too small for that many codes.")
    pix = img.load()
    count = f"{len(a.codes):09b}"
    for p in range(HEADER_PIXELS):
        write_bits(pix, p, img.width, [int(b) for b in count[p * 3:(p + 1) * 3]])
    for i, code in enumerate(a.codes):
        write_bits(pix, HEADER_PIXELS + i, img.width, [int(b) for b in code])
        print(f"embedded {code} -> {book[code]}")
    img.save(a.output)
    print(f"Saved {a.output}")


def extract(a):
    book = load_codebook(a.codebook)
    img = Image.open(a.stego).convert("RGB")
    pix = img.load()
    count = int("".join(str(b) for p in range(HEADER_PIXELS) for b in read_bits(pix, p, img.width)), 2)
    for i in range(count):
        code = "".join(str(b) for b in read_bits(pix, HEADER_PIXELS + i, img.width))
        print(f"{code} -> {book.get(code, '<unknown code>')}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("embed")
    e.add_argument("cover")
    e.add_argument("output")
    e.add_argument("--codebook", required=True)
    e.add_argument("--codes", nargs="+", required=True)
    x = sub.add_parser("extract")
    x.add_argument("stego")
    x.add_argument("--codebook", required=True)
    a = ap.parse_args()
    embed(a) if a.cmd == "embed" else extract(a)


if __name__ == "__main__":
    main()
