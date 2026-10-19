#!/usr/bin/env python3
"""Read-only LP10 probe: port scan + UDP-1800 identity.

Identity uses the same LSSDP M-SEARCH the integration's discovery uses.
Control-port (2018) status is better read with the integration's own
custom_components/arylic_lp10/protocol.py LP10Client; this tool just covers
reachability and identity without importing the component.

Usage: python lp10_probe.py <ip>
"""
from __future__ import annotations
import socket, sys

PORTS = {
    80: "httpapi host (disabled on AR241CP_8747)",
    2018: "control port (LP10Client)",
    5555: "ADB (absent on AR241CP_8747)",
    7777: "luciserver lucinetwork (mutual-TLS LUCI / metadata)",
    9090: "dynamically-bound service (not metadata)",
    49494: "UPnP renderer (per-boot; discover via SSDP)",
}

def tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def identity(host: str, timeout: float = 1.0) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    req = (f"M-SEARCH * HTTP/1.1\r\nHOST: 0.0.0.0:{port}\r\n\r\nPROTOCOL: Version 1.0").encode()
    out: dict[str, str] = {}
    try:
        s.sendto(req, (host, 1800))
        payload, peer = s.recvfrom(8192)
        if peer[0] == host:
            for line in payload.decode("utf-8", "replace").replace("\r", "").split("\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip().lower()] = v.strip()[:128]
    except OSError:
        pass
    finally:
        s.close()
    return out

def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "10.200.10.3"
    print(f"== {host} identity (UDP 1800) ==")
    ident = identity(host)
    for k in ("devicename", "cast_model", "fwversion", "usn", "netmode"):
        if k in ident:
            print(f"  {k}: {ident[k]}")
    print(f"== {host} ports ==")
    for p, note in PORTS.items():
        print(f"  {p:<6} {'open' if tcp_open(host, p) else 'closed':<7} {note}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
