#!/usr/bin/env python3
"""Mutual-TLS client scaffold for the LP10 LUCI "lucinetwork" service (TCP 7777).

Research tool for reading now-playing metadata (MID 42) on LP10 firmware that has
no ADB. See docs/research/luci-metadata/. READ-ONLY by intent: only builds GET-ish
zero-length frames. Do not add SET/write frames until the command semantics are
fully confirmed.

Status: TLS handshake + frame build/parse work. The server NACKs data requests
until a *register* packet is sent first — that handshake is the remaining gap
(docs/research/luci-metadata/remaining-work.md).

Requires the extracted client cert/key (docs/research/luci-metadata/client-certificate.md):
    client.pem, client.key

Examples:
    python luci_tls_client.py --host 10.200.10.3 --handshake
    python luci_tls_client.py --host 10.200.10.3 --read-mid 42   # currently NACKs (register first)
"""
from __future__ import annotations
import argparse, socket, ssl, sys, time, re

# --- CRC-16/XMODEM (poly 0x1021, init 0x0000), big-endian on the wire at [6:7] ---
def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc

# --- LUCI packet frame: 10-byte header, payload from byte 10 -------------------
# Header offsets (see docs/research/luci-metadata/luci-protocol.md):
#   [0:2] u16, [2] u8, [3:5] u16 BE = ID/MID, [5] u8,
#   [6:8] u16 BE = CRC (XMODEM, computed with this field zeroed),
#   [8:10] u16 LE = DataLen, [10:] payload.
# The Command/Type/Status split among {0,2,5} is not yet pinned; `b0/b2/b5` expose them.
def build_frame(mid: int = 0, b0: int = 0, b2: int = 0, b5: int = 0, payload: bytes = b"") -> bytes:
    b = bytearray(10 + len(payload))
    b[0] = b0 & 0xFF
    b[1] = (b0 >> 8) & 0xFF
    b[2] = b2 & 0xFF
    b[3] = (mid >> 8) & 0xFF        # ID/MID big-endian
    b[4] = mid & 0xFF
    b[5] = b5 & 0xFF
    b[8] = len(payload) & 0xFF      # DataLen little-endian
    b[9] = (len(payload) >> 8) & 0xFF
    if payload:
        b[10:] = payload
    crc = crc16_xmodem(bytes(b))    # CRC field already 0
    b[6] = (crc >> 8) & 0xFF        # CRC big-endian
    b[7] = crc & 0xFF
    return bytes(b)

def parse_header(pkt: bytes) -> dict:
    if len(pkt) < 10:
        return {"raw": pkt.hex()}
    return {
        "b0": int.from_bytes(pkt[0:2], "little"),
        "b2": pkt[2],
        "id_mid": int.from_bytes(pkt[3:5], "big"),
        "b5": pkt[5],
        "crc": int.from_bytes(pkt[6:8], "big"),
        "len": int.from_bytes(pkt[8:10], "little"),
        "payload": pkt[10:],
    }

def connect(host: str, port: int, cert: str, key: str, timeout: float = 8.0) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # server cert chains to a private CA
    ctx.load_cert_chain(cert, key)           # our client cert (mutual TLS)
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    raw = socket.create_connection((host, port), timeout=timeout)
    s = ctx.wrap_socket(raw, server_hostname=None)
    s.settimeout(timeout)
    return s

def send_recv(s: ssl.SSLSocket, pkt: bytes, wait: float = 1.0, cap: int = 65536) -> bytes:
    s.sendall(pkt)
    time.sleep(0.3)
    out = bytearray()
    s.settimeout(wait)
    try:
        while len(out) < cap:
            d = s.recv(4096)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    return bytes(out)

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--cert", default="client.pem")
    ap.add_argument("--key", default="client.key")
    ap.add_argument("--handshake", action="store_true", help="just confirm mutual TLS")
    ap.add_argument("--read-mid", type=int, help="attempt a read of this MID (NACKs until register is implemented)")
    ap.add_argument("--b0", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--b2", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--b5", type=lambda x: int(x, 0), default=0)
    args = ap.parse_args()

    s = connect(args.host, args.port, args.cert, args.key)
    print(f"TLS OK: {s.version()} {s.cipher()[0]}")
    if args.handshake and args.read_mid is None:
        s.close()
        return 0

    mid = args.read_mid if args.read_mid is not None else 0
    pkt = build_frame(mid=mid, b0=args.b0, b2=args.b2, b5=args.b5)
    print("send:", pkt.hex())
    resp = send_recv(s, pkt)
    s.close()
    hdr = parse_header(resp)
    ascii_runs = b" | ".join(re.findall(rb"[ -~]{4,}", resp))
    print("recv:", resp.hex())
    print("parsed:", {k: (v.hex() if isinstance(v, bytes) else v) for k, v in hdr.items()})
    if ascii_runs:
        print("ascii:", ascii_runs.decode("latin1"))
    return 0

if __name__ == "__main__":
    sys.exit(main())
