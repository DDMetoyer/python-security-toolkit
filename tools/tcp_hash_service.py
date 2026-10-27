#!/usr/bin/env python3
"""tcp_hash_service.py - TCP integrity-check service: the server returns the hash of whatever it receives.

The client sends a message (or a file) and compares the digest the server
computed with one computed locally, which verifies the data arrived intact.

Usage:
    python tcp_hash_service.py server [--port 5555] [--algo sha256]
    python tcp_hash_service.py client "message text" [--host 127.0.0.1] [--port 5555] [--algo sha256]
    python tcp_hash_service.py client --file report.pdf
"""
import argparse
import hashlib
import socket


def recv_all(conn):
    chunks = []
    while chunk := conn.recv(65536):
        chunks.append(chunk)
    return b"".join(chunks)


def server(a):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a.bind, a.port))
        s.listen(5)
        print(f"Listening on {a.bind}:{a.port} ({a.algo})")
        try:
            while True:
                conn, addr = s.accept()
                with conn:
                    data = recv_all(conn)
                    digest = hashlib.new(a.algo, data).hexdigest()
                    conn.sendall(digest.encode())
                    print(f"{addr[0]}:{addr[1]}  {len(data)} bytes  {a.algo}={digest}")
        except KeyboardInterrupt:
            print("\nServer stopped.")


def client(a):
    data = open(a.file, "rb").read() if a.file else (a.message or "").encode()
    with socket.create_connection((a.host, a.port), timeout=10) as s:
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)  # signal end of message
        remote = s.recv(1024).decode()
    local = hashlib.new(a.algo, data).hexdigest()
    print(f"Sent {len(data)} bytes")
    print(f"Server {a.algo}: {remote}")
    print(f"Local  {a.algo}: {local}")
    print("MATCH - data intact" if remote == local else "MISMATCH - data altered in transit")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("server")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5555)
    s.add_argument("--algo", default="sha256", choices=sorted(hashlib.algorithms_guaranteed))
    c = sub.add_parser("client")
    c.add_argument("message", nargs="?")
    c.add_argument("--file")
    c.add_argument("--host", default="127.0.0.1")
    c.add_argument("--port", type=int, default=5555)
    c.add_argument("--algo", default="sha256", choices=sorted(hashlib.algorithms_guaranteed))
    a = ap.parse_args()
    server(a) if a.cmd == "server" else client(a)


if __name__ == "__main__":
    main()
