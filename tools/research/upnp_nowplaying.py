#!/usr/bin/env python3
"""SSDP-discover the LP10 UPnP MediaRenderer and read AVTransport/RenderingControl.

Read-only. Gives transport state, volume, mute, and (only for DLNA-pushed playback)
track metadata. For NET/streaming sources the renderer reports STOPPED with no
metadata — see docs/research/luci-metadata/device-findings.md.

Usage: python upnp_nowplaying.py <ip>
"""
from __future__ import annotations
import re, socket, sys, urllib.request

def discover(host: str, timeout: float = 3.0) -> str | None:
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
           'MAN:"ssdp:discover"\r\nMX:2\r\n'
           "ST:urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(msg, (host, 1900))
    try:
        while True:
            data, addr = s.recvfrom(4096)
            if addr[0] == host:
                m = re.search(rb"LOCATION:\s*(\S+)", data, re.I)
                if m:
                    return m.group(1).decode()
    except socket.timeout:
        return None

def soap(url: str, service: str, action: str, body: str) -> str:
    env = (f'<?xml version="1.0"?>'
           f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
           f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
           f'<s:Body>{body}</s:Body></s:Envelope>').encode()
    req = urllib.request.Request(url, data=env, headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPACTION": f'"urn:schemas-upnp-org:service:{service}#{action}"',
    })
    with urllib.request.urlopen(req, timeout=8) as r:
        return r.read().decode("utf-8", "replace")

def unescape(x: str) -> str:
    return (x.replace("&lt;", "<").replace("&gt;", ">")
             .replace("&quot;", '"').replace("&amp;", "&"))

def grab(xml: str, tag: str) -> str:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.S)
    return unescape(m.group(1)) if m else ""

def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "10.200.10.3"
    loc = discover(host)
    if not loc:
        print("no renderer found via SSDP"); return 1
    base = re.match(r"(https?://[^/]+)", loc).group(1)
    desc = urllib.request.urlopen(loc, timeout=8).read().decode("utf-8", "replace")
    print("renderer:", base, "name:", grab(desc, "friendlyName"))
    T = base + "/upnp/control/rendertransport1"
    R = base + "/upnp/control/rendercontrol1"
    av = "AVTransport:1"; rc = "RenderingControl:1"

    ti = soap(T, av, "GetTransportInfo",
              f'<u:GetTransportInfo xmlns:u="urn:schemas-upnp-org:service:{av}"><InstanceID>0</InstanceID></u:GetTransportInfo>')
    print("state:", grab(ti, "CurrentTransportState"))
    vol = soap(R, rc, "GetVolume",
               f'<u:GetVolume xmlns:u="urn:schemas-upnp-org:service:{rc}"><InstanceID>0</InstanceID><Channel>Master</Channel></u:GetVolume>')
    print("volume:", grab(vol, "CurrentVolume"))
    mute = soap(R, rc, "GetMute",
                f'<u:GetMute xmlns:u="urn:schemas-upnp-org:service:{rc}"><InstanceID>0</InstanceID><Channel>Master</Channel></u:GetMute>')
    print("mute:", grab(mute, "CurrentMute"))
    pos = soap(T, av, "GetPositionInfo",
               f'<u:GetPositionInfo xmlns:u="urn:schemas-upnp-org:service:{av}"><InstanceID>0</InstanceID></u:GetPositionInfo>')
    print("duration:", grab(pos, "TrackDuration"), "pos:", grab(pos, "RelTime"))
    meta = grab(pos, "TrackMetaData")
    print("track metadata (empty for NET sources):", meta[:400] if meta else "(none)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
