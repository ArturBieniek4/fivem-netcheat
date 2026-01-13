#!/usr/bin/env python3
import argparse
import selectors
import socket
import struct
import sys
import time
from typing import Optional, Tuple

Addr = Tuple[str, int]

def parse_hostport(s: str) -> Addr:
    # supports "host:port" (host may be IP or name)
    if s.count(":") == 0:
        raise ValueError("Expected host:port")
    host, port_s = s.rsplit(":", 1)
    return host, int(port_s)

def hexdump_prefix(data: bytes, n: int = 32) -> str:
    b = data[:n]
    return " ".join(f"{x:02x}" for x in b)

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Selective UDP proxy: if first 32 bits == 0xFFFFFFFF passthrough, else divert."
        )
    ap.add_argument("--listen", default="0.0.0.0:50121", help="Listen address, e.g. 0.0.0.0:50121")
    ap.add_argument("--upstream", required=True, help="Upstream server host:port, e.g. 34.116.239.21:30120")
    ap.add_argument(
        "--divert",
        default=None,
        help="Divert target host:port for non-FFFFFFFF packets (optional). If omitted, non-FFFFFFFF packets are dropped.",
    )
    ap.add_argument("--verbose", action="store_true", help="Log decisions and short hexdumps")
    ap.add_argument("--idle-timeout", type=int, default=300, help="Forget client after N seconds idle (default 300)")
    args = ap.parse_args()

    listen_addr = parse_hostport(args.listen)
    upstream_addr = parse_hostport(args.upstream)
    divert_addr = parse_hostport(args.divert) if args.divert else None

    sel = selectors.DefaultSelector()

    # Socket that receives from local client(s) AND sends replies back to them.
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    listen_sock.bind(listen_addr)
    listen_sock.setblocking(False)
    sel.register(listen_sock, selectors.EVENT_READ, data=("listen", None))

    # One upstream socket (stable source port -> stable server-side session).
    up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up_sock.connect(upstream_addr)
    up_sock.setblocking(False)
    sel.register(up_sock, selectors.EVENT_READ, data=("upstream", upstream_addr))

    # Optional divert socket.
    div_sock = None
    if divert_addr:
        div_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        div_sock.connect(divert_addr)
        div_sock.setblocking(False)
        sel.register(div_sock, selectors.EVENT_READ, data=("divert", divert_addr))

    last_client: Optional[Addr] = None
    last_client_ts: float = 0.0

    if args.verbose:
        print(f"[+] Listening on {listen_addr[0]}:{listen_addr[1]}", flush=True)
        print(f"[+] Upstream: {upstream_addr[0]}:{upstream_addr[1]}", flush=True)
        if divert_addr:
            print(f"[+] Divert:   {divert_addr[0]}:{divert_addr[1]}", flush=True)
        else:
            print("[+] Divert:   (drop non-FFFFFFFF)", flush=True)

    while True:
        # Expire client mapping if idle too long
        if last_client and (time.time() - last_client_ts) > args.idle_timeout:
            if args.verbose:
                print(f"[-] Forgetting idle client {last_client}", flush=True)
            last_client = None

        events = sel.select(timeout=1.0)
        for key, _mask in events:
            sock = key.fileobj
            role, _info = key.data

            if role == "listen":
                try:
                    data, addr = listen_sock.recvfrom(65535)
                except BlockingIOError:
                    continue

                last_client = addr
                last_client_ts = time.time()

                first32 = None
                if len(data) >= 4:
                    # Endianness doesn't matter for 0xFFFFFFFF equality check, but use network order anyway.
                    first32 = struct.unpack("!I", data[:4])[0]

                if first32 == 0xFFFFFFFF:
                    # passthrough to upstream
                    up_sock.send(data)
                    if args.verbose:
                        print(f"[C->U] {addr} len={len(data)} first32=FFFFFFFF  {hexdump_prefix(data)}", flush=True)
                else:
                    # divert or drop
                    if div_sock:
                        div_sock.send(data)
                        if args.verbose:
                            v = "None" if first32 is None else f"{first32:08X}"
                            print(f"[C->D] {addr} len={len(data)} first32={v}  {hexdump_prefix(data)}", flush=True)
                    else:
                        if args.verbose:
                            v = "None" if first32 is None else f"{first32:08X}"
                            print(f"[DROP] {addr} len={len(data)} first32={v}", flush=True)

            elif role in ("upstream", "divert"):
                # Read reply from upstream/divert and forward to last_client
                try:
                    data = sock.recv(65535)
                except BlockingIOError:
                    continue

                if not last_client:
                    if args.verbose:
                        print(f"[DROP] reply {role} len={len(data)} (no client yet)", flush=True)
                    continue

                # Send reply back to client from the listen socket (important for transparent-ish behavior)
                listen_sock.sendto(data, last_client)
                if args.verbose:
                    tag = "U->C" if role == "upstream" else "D->C"
                    print(f"[{tag}] {last_client} len={len(data)}  {hexdump_prefix(data)}", flush=True)

    # unreachable
    # return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[+] Exiting", file=sys.stderr)
        raise SystemExit(0)

