# Research tools

Read-only helpers used while reverse-engineering LAN metadata access on LP10
firmware without ADB. Background: [`docs/research/luci-metadata/`](../../docs/research/luci-metadata/).

| Script | What it does |
| --- | --- |
| `lp10_probe.py <ip>` | UDP-1800 identity + TCP port scan (reachability). |
| `upnp_nowplaying.py <ip>` | SSDP-discover the renderer; read state/volume/mute/position. |
| `ota_fetch.py --device-id <id>` | Ask the OTA server for the current firmware URL. |
| `luci_client.py --host <ip> --auth-only` | **Working authenticated client**: mutual-TLS + Basic auth (CmdID 3) + MCU query tunnel (CmdID 64) + frame parser. Verified live. |
| `luci_tls_client.py --host <ip> --handshake` | Earlier low-level TLS/frame scaffold; superseded by `luci_client.py`, kept for reference. |

## Setup

```sh
python3 -m venv venv && . venv/bin/activate
pip install crcmod          # only luci_tls_client.py's CRC is inlined; crcmod optional
# luci_tls_client.py needs the extracted client cert/key beside it:
#   see docs/research/luci-metadata/client-certificate.md
```

Everything here is read-only against the devices. `luci_client.py` sends only MCU
`+GET&`/`+INF&` queries; do not add MCU SET commands (e.g. `MCU+VOL+<n>&`) until
each is understood. The handshake is documented in
`docs/research/luci-metadata/handshake-solved.md`.
