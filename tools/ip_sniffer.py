#!/usr/bin/env python3
"""ip_sniffer.py - Raw-socket IPv4 sniffer that summarizes conversations.

Captures N packets, decodes the IPv4 header of each, and prints a table of
unique (source, destination, protocol) flows ranked by packet count.

Requires administrator/root privileges.
  * Windows: binds a raw IP socket to the host address in promiscuous mode (SIO_RCVALL).
  * Linux:   uses an AF_PACKET socket and strips the 14-byte Ethernet header.

Usage:
    sudo python ip_sniffer.py [--count 1000] [--host 192.168.1.10] [--quiet]

IP header parsing is adapted from the sniffer example in *Black Hat Python*
(Seitz & Arnold, No Starch Press).
"""
import argparse
import ipaddress
import os
import socket
import struct
from collections import Counter

from prettytable import PrettyTable

PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
ETH_P_IP = 0x0800


class IPHeader:
    """Decodes the fixed 20-byte IPv4 header (network byte order)."""

    def __init__(self, raw):
        f = struct.unpack("!BBHHHBBH4s4s", raw[:20])
        self.version = f[0] >> 4
        self.ihl = f[0] & 0xF
        self.tos, self.length, self.id, self.frag = f[1], f[2], f[3], f[4]
        self.ttl, self.proto_num, self.checksum = f[5], f[6], f[7]
        self.src = ipaddress.ip_address(f[8])
        self.dst = ipaddress.ip_address(f[9])
        self.protocol = PROTOCOLS.get(self.proto_num, str(self.proto_num))


def open_socket(host):
    if os.name == "nt":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((host, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return s, 0
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IP))
    return s, 14  # skip Ethernet header


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--host", default=None, help="interface IP to bind (Windows); default: this host")
    ap.add_argument("--quiet", action="store_true", help="don't print each packet")
    a = ap.parse_args()

    host = a.host or socket.gethostbyname(socket.gethostname())
    sniffer, offset = open_socket(host)
    flows = Counter()
    print(f"Capturing {a.count} IPv4 packets... (Ctrl-C to stop early)")
    try:
        for _ in range(a.count):
            raw = sniffer.recvfrom(65535)[0][offset:]
            if len(raw) < 20:
                continue
            ip = IPHeader(raw)
            if ip.version != 4:
                continue
            flows[(str(ip.src), str(ip.dst), ip.protocol)] += 1
            if not a.quiet:
                print(f"{str(ip.src):>15} -> {str(ip.dst):<15} {ip.protocol:<5} ttl={ip.ttl} len={ip.length}")
    except KeyboardInterrupt:
        pass
    finally:
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer.close()

    t = PrettyTable(["Packets", "Source", "Destination", "Protocol"])
    for (src, dst, proto), n in flows.most_common():
        t.add_row([n, src, dst, proto])
    print(f"\nUnique flows: {len(flows)}")
    print(t)


if __name__ == "__main__":
    main()
