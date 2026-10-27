#!/usr/bin/env python3
"""web_recon.py - Same-domain web crawler for passive reconnaissance.

Starting from one URL, crawls every page on the same host and reports:
  * unique page URLs and image URLs
  * phone numbers and ZIP codes found in page text
  * (optional) vocabulary, nouns and verbs via NLTK part-of-speech tagging
  * (optional) downloads every image for offline metadata analysis

Only crawl sites you own or are authorized to assess.

Usage:
    python web_recon.py https://example.com [--out report.txt] [--nlp] [--download-images DIR]
                        [--exclude URL ...] [--max-pages 200] [--delay 0.5]
"""
import argparse
import os
import re
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
PHONE_RE = re.compile(r"(?:\+\d{1,3}[-.\s]*)?\(?\d{3}\)?[-.\s]*\d{3}[-.\s]*\d{4}\b")
UA = {"User-Agent": "web_recon/1.0 (+authorized security assessment)"}


def normalize(base, link):
    return urljoin(base, link.split("#")[0])


def crawl(start, exclude, max_pages, delay):
    domain = urlparse(start).netloc
    queue, visited = [start], set()
    pages, images, phones, zips, texts = set(), set(), set(), set(), []
    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited or url in exclude:
            continue
        visited.add(url)
        try:
            r = requests.get(url, headers=UA, timeout=10)
        except requests.RequestException as e:
            print(f"[error] {url}: {e}")
            continue
        if "html" not in r.headers.get("content-type", ""):
            continue
        print(f"[crawl] {url}")
        pages.add(url)
        soup = BeautifulSoup(r.text, "html.parser")
        text = soup.get_text(separator="\n", strip=True)
        texts.append(text)
        phones.update(m.group(0).strip() for m in PHONE_RE.finditer(text))
        zips.update(ZIP_RE.findall(text))
        for img in soup.find_all("img", src=True):
            src = normalize(url, img["src"])
            if src not in exclude:
                images.add(src)
        for a in soup.find_all("a", href=True):
            link = normalize(url, a["href"])
            if urlparse(link).netloc == domain and link not in visited and link not in exclude:
                queue.append(link)
        time.sleep(delay)
    return pages, images, phones, zips, "\n".join(texts)


def nlp(text):
    import nltk
    for pkg in ("punkt", "punkt_tab", "averaged_perceptron_tagger", "averaged_perceptron_tagger_eng"):
        nltk.download(pkg, quiet=True)
    tokens = nltk.word_tokenize(text)
    tagged = nltk.pos_tag(tokens)
    vocab = {w.lower() for w in tokens if w.isalpha()}
    verbs = {w.lower() for w, t in tagged if t.startswith("VB") and w.isalpha()}
    nouns = {w.lower() for w, t in tagged if t in ("NN", "NNS") and w.isalpha()} - verbs
    return vocab, verbs, nouns


def download(images, folder):
    os.makedirs(folder, exist_ok=True)
    for url in sorted(images):
        name = os.path.basename(urlparse(url).path) or "image"
        try:
            r = requests.get(url, headers=UA, timeout=10)
            r.raise_for_status()
            with open(os.path.join(folder, name), "wb") as f:
                f.write(r.content)
            print(f"[saved] {name}")
        except requests.RequestException as e:
            print(f"[error] {url}: {e}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url")
    ap.add_argument("--out", default="recon_report.txt")
    ap.add_argument("--nlp", action="store_true", help="add vocabulary / noun / verb analysis (requires nltk)")
    ap.add_argument("--download-images", metavar="DIR")
    ap.add_argument("--exclude", nargs="*", default=[], help="URLs to skip")
    ap.add_argument("--max-pages", type=int, default=200)
    ap.add_argument("--delay", type=float, default=0.5, help="seconds between requests")
    a = ap.parse_args()

    pages, images, phones, zips, text = crawl(a.url, set(a.exclude), a.max_pages, a.delay)
    sections = [("Pages", pages), ("Images", images), ("Phone numbers", phones), ("ZIP codes", zips)]
    if a.nlp:
        vocab, verbs, nouns = nlp(text)
        sections += [("Vocabulary", vocab), ("Verbs", verbs), ("Nouns", nouns)]

    with open(a.out, "w", encoding="utf-8") as f:
        for title, items in sections:
            f.write(f"{title} ({len(items)}):\n")
            f.writelines(f"  {i}\n" for i in sorted(items))
            f.write("\n")
    for title, items in sections:
        print(f"{title}: {len(items)}")
    print(f"Report written to {a.out}")

    if a.download_images:
        download(images, a.download_images)


if __name__ == "__main__":
    main()
