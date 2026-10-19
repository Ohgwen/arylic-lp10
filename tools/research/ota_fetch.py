#!/usr/bin/env python3
"""Query the Arylic/rakoit OTA server for the current LP10 firmware URL.

The endpoint is a JSON POST API (not a file server) and only returns the current
build. See docs/research/luci-metadata/firmware-analysis.md. Be gentle: this is
the same server your players use for real update checks.

Usage:
    python ota_fetch.py --device-id d8f71071384c [--fw AR241CP_8747.29.2] [--model LP10]
"""
from __future__ import annotations
import argparse, json, urllib.request

ENDPOINT = "https://lp10.arylic.rakoit-ota.com/v1"

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--device-id", required=True, help="12-hex device id (USN from identity)")
    ap.add_argument("--fw", default="AR241CP_8747.29.2")
    ap.add_argument("--model", default="LP10")
    ap.add_argument("--brand", default="Arylic")
    args = ap.parse_args()
    body = json.dumps({"device": {
        "brand": args.brand, "deviceId": args.device_id,
        "fwVersion": args.fw, "model": args.model,
    }}).encode()
    req = urllib.request.Request(ENDPOINT, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        print(r.read().decode())
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
