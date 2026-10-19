#!/usr/bin/env python3
"""Authenticated LUCI client for the LP10 "lucinetwork" service (TCP 7777).

This is the working client that resulted from reversing the handshake. On
AR241CP_8747 firmware (no ADB), it:

  1. opens a mutual-TLS connection with the extracted client cert,
  2. authenticates with HTTP Basic credentials wrapped in JSON, sent on
     CmdID 3 (the server's dispatcher treats offset-3 == 3 as "authenticate"),
  3. then tunnels A31 MCU "MCU+...+GET&" queries to the UART controller on
     CmdID 64 and reads the "AXX+..." replies.

See docs/research/luci-metadata/handshake-solved.md for the full derivation.

READ-ONLY by intent: only sends MCU "+GET"/"+INF" queries. Do not add SET/write
commands until each one is understood.

Requires the extracted client cert/key beside it (client.pem, client.key):
  see docs/research/luci-metadata/client-certificate.md

Examples:
  python luci_client.py --host 10.200.10.3 --auth-only
  python luci_client.py --host 10.200.10.3 --query 'MCU+VOL+GET&'
  python luci_client.py --host 10.200.10.3 --listen 5     # drain pushed frames
"""
from __future__ import annotations
import argparse, base64, json, socket, ssl, sys, time

AUTH_CMDID = 3        # offset-3 value the server dispatches to AuthenticateLuciClient
UART_CMDID = 64       # 0x40: the UART tunnel controller (A31 MCU / AXX commands)
DEFAULT_USER = "admin"       # env Defaultwebusername (Newwebusername is empty)
DEFAULT_PASS = "Wireless"    # env Defaultwebuserpassword


# --- CRC-16/XMODEM (poly 0x1021, init 0x0000), little-endian on the wire at [6:8] ---
def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


# --- LUCI frame (requests we send) --------------------------------------------
# 10-byte header + payload. Offsets:
#   [0:2]  u16   (unused by us; 0)
#   [2]    u8    Type (0 for our requests)
#   [3:5]  u16LE CmdID  (3 = auth, 64 = UART tunnel, ...)  <- dispatch key
#   [5]    u8    Status (0)
#   [6:8]  u16LE CRC-16/XMODEM, computed with this field zeroed
#   [8:10] u16LE DataLen
#   [10:]        payload
def build_frame(cmdid: int, payload: bytes = b"", typ: int = 0, status: int = 0) -> bytes:
    b = bytearray(10 + len(payload))
    b[2] = typ & 0xFF
    b[3] = cmdid & 0xFF
    b[4] = (cmdid >> 8) & 0xFF
    b[5] = status & 0xFF
    b[8] = len(payload) & 0xFF
    b[9] = (len(payload) >> 8) & 0xFF
    if payload:
        b[10:] = payload
    c = crc16_xmodem(bytes(b))
    b[6] = c & 0xFF
    b[7] = (c >> 8) & 0xFF
    return bytes(b)


def parse_frames(buf: bytes) -> list[dict]:
    """Split a received byte stream into LUCI frames.

    NOTE the asymmetry: the device writes DataLen BIG-endian in replies/pushes,
    while our requests use little-endian. We try LE first and fall back to BE,
    which disambiguates cleanly for the small lengths seen in practice.
    """
    out: list[dict] = []
    i, n = 0, len(buf)
    while i + 10 <= n:
        typ = buf[i + 2]
        cmdid = int.from_bytes(buf[i + 3:i + 5], "little")
        status = buf[i + 5]
        ln = int.from_bytes(buf[i + 8:i + 10], "little")
        if i + 10 + ln > n:
            ln = int.from_bytes(buf[i + 8:i + 10], "big")
            if i + 10 + ln > n:
                out.append({"truncated": buf[i:].hex()})
                break
        out.append({
            "type": typ, "cmdid": cmdid, "status": status,
            "len": ln, "payload": bytes(buf[i + 10:i + 10 + ln]),
        })
        i += 10 + ln
    return out


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


def recv_for(s: ssl.SSLSocket, seconds: float, cap: int = 131072) -> bytes:
    out = bytearray()
    end = time.time() + seconds
    s.settimeout(seconds)
    while time.time() < end and len(out) < cap:
        try:
            d = s.recv(8192)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    return bytes(out)


def authenticate(s: ssl.SSLSocket, user: str, password: str, wait: float = 1.5) -> bool:
    val = base64.b64encode(f"{user}:{password}".encode()).decode()
    payload = json.dumps({"Authentication": "Basic", "Value": val}).encode()
    s.sendall(build_frame(AUTH_CMDID, payload))
    reply = recv_for(s, wait)
    # auth OK -> reply status byte (offset 5) == 1; NACK == 3
    return len(reply) >= 6 and reply[5] == 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--cert", default="client.pem")
    ap.add_argument("--key", default="client.key")
    ap.add_argument("--user", default=DEFAULT_USER)
    ap.add_argument("--password", default=DEFAULT_PASS)
    ap.add_argument("--auth-only", action="store_true", help="just confirm auth")
    ap.add_argument("--query", action="append", default=[],
                    help="MCU query to tunnel on CmdID 64, e.g. 'MCU+VOL+GET&' (repeatable)")
    ap.add_argument("--listen", type=float, default=0.0,
                    help="after queries, drain pushed frames for N seconds")
    args = ap.parse_args()

    s = connect(args.host, args.port, args.cert, args.key)
    print(f"TLS OK: {s.version()} {s.cipher()[0]}")
    if not authenticate(s, args.user, args.password):
        print("AUTH FAILED (check credentials / client cert)")
        s.close()
        return 1
    print(f"AUTH OK as {args.user!r}")
    if args.auth_only and not args.query and not args.listen:
        s.close()
        return 0

    for q in args.query:
        s.sendall(build_frame(UART_CMDID, q.encode()))
    buf = recv_for(s, args.listen or 3.0)
    s.close()

    for f in parse_frames(buf):
        if "truncated" in f:
            print(f"  <truncated {len(f['truncated'])//2}B>")
            continue
        pl = f["payload"]
        if pl:
            print(f"  cmdid={f['cmdid']:#06x} type={f['type']} status={f['status']} "
                  f"len={f['len']}: {pl.decode('latin1')!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
