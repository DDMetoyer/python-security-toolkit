# Python Security Toolkit

**Nine small command-line tools for forensics triage, reconnaissance and network analysis.** Each one is a single file with no framework, its own `--help`, and a focus on one job.

| Tool | What it does | Typical use |
|---|---|---|
| [`file_triage.py`](tools/file_triage.py) | Recursively hashes files (MD5 + SHA-256), records size and MAC times, dumps the first 20 header bytes and flags duplicates | Evidence intake, spotting renamed file types |
| [`log_triage.py`](tools/log_triage.py) | Counts antivirus worm detections in syslog and extracts auth failures and request-flood warnings | First-pass log review |
| [`ioc_extract.py`](tools/ioc_extract.py) | Streams through memory dumps or any binary and carves e-mail addresses, URLs and readable strings, ranked by frequency | Memory forensics, malware triage |
| [`exif_gps.py`](tools/exif_gps.py) | Pulls GPS coordinates, capture time and camera make/model from JPEG EXIF and exports a map-ready CSV | Image geolocation / OSINT |
| [`web_recon.py`](tools/web_recon.py) | Same-domain crawler that collects pages, images, phone numbers and ZIP codes, with optional NLTK noun/verb analysis and image download | Passive recon of an authorized target |
| [`ip_sniffer.py`](tools/ip_sniffer.py) | Raw-socket IPv4 sniffer (Windows and Linux) that decodes headers and ranks flows by packet count | Quick network visibility without Wireshark |
| [`lsb_stego.py`](tools/lsb_stego.py) | Hides and recovers codebook messages in the least-significant bits of BMP/PNG pixels | Covert-channel demonstration, stego CTFs |
| [`vt_hash_lookup.py`](tools/vt_hash_lookup.py) | Hashes a folder of samples and checks each hash against VirusTotal (no upload) | Malware sample triage |
| [`tcp_hash_service.py`](tools/tcp_hash_service.py) | TCP client/server that verifies data integrity by comparing server-side and local hashes | Socket programming, integrity checks |

## Quick start

```bash
git clone https://github.com/DDMetoyer/python-security-toolkit
cd python-security-toolkit
pip install -r requirements.txt
python tools/<tool>.py --help
```

## Sample output

**`exif_gps.py`**: geolocating a folder of photos

```text
File            | Latitude  | Longitude  | Timestamp           | Make   | Model
Turtle.jpg      | 25.338400 | 34.739666  | 2008:05:08 16:55:58 | Canon  | Canon EOS 5D
barn.jpg        | 42.501235 | -83.250663 | 2009:03:14 13:46:34 | NIKON  | COOLPIX P6000
kinderscout.jpg | No GPS    | No GPS     | 2008:01:12 12:06:52 | NIKON CORPORATION | NIKON D50

2 geotagged images written to image_gps_data.csv
```

**`log_triage.py`**: 400 KB of mail-server syslog

```text
=== Malware detections ===
Worm             | Detections
SomeFool.Gen-2   | 1092
SomeFool.Gen-1   | 683
Mydoom.F         | 46
SomeFool.I       | 43
Sobig.F          | 15
...
```

**`ip_sniffer.py`**

```text
Capturing 1000 IPv4 packets... (Ctrl-C to stop early)
Unique flows: 2
Packets | Source        | Destination | Protocol
3       | 160.79.104.10 | 192.0.2.2   | TCP
3       | 127.0.0.1     | 127.0.0.1   | TCP
```

**`lsb_stego.py`**

```text
$ python tools/lsb_stego.py embed cover.bmp hidden.bmp --codebook codebook.txt --codes 101 011
embedded 101 -> 12 PM Sharp
embedded 011 -> Drop Package in Potted Plant outside Wells Fargo
$ python tools/lsb_stego.py extract hidden.bmp --codebook codebook.txt
101 -> 12 PM Sharp
011 -> Drop Package in Potted Plant outside Wells Fargo
```

## Design notes

- **Streaming I/O.** `ioc_extract.py` reads 1 MB chunks with a 256-byte overlap, so multi-GB memory images work and matches that straddle chunk boundaries aren't lost or double-counted.
- **Network byte order.** `ip_sniffer.py` unpacks headers with `!` (big-endian), so length and ID fields decode correctly.
- **Secrets stay out of code.** `vt_hash_lookup.py` reads `VT_API_KEY` from the environment and only sends hashes, never the samples.
- **Polite crawling.** `web_recon.py` stays on one host, rate-limits requests, honors an exclusion list and caps page count.

## Status

All tools were tested against sample data except `vt_hash_lookup.py`, which needs a live API key; it targets the VirusTotal v3 API.

## Legal

Use these tools only on systems and data you own or are explicitly authorized to assess.

## Credits and license

MIT © Devante Metoyer. Two tools adapt published or provided example code; see [CREDITS.md](CREDITS.md).
