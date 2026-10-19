# Research tools

Read-only helpers used while reverse-engineering LAN metadata access on LP10
firmware without ADB. Background: [`docs/research/luci-metadata/`](../../docs/research/luci-metadata/).

| Script | What it does |
| --- | --- |
| `lp10_probe.py <ip>` | UDP-1800 identity + TCP port scan (reachability). |
| `upnp_nowplaying.py <ip>` | SSDP-discover the renderer; read state/volume/mute/position. |
| `ota_fetch.py --device-id <id>` | Ask the OTA server for the current firmware URL. |
| `luci_tls_client.py --host <ip> --handshake` | Mutual-TLS to 7777 with the client cert; build/parse LUCI frames. The scaffold to finish the register handshake on. |

## Setup

```sh
python3 -m venv venv && . venv/bin/activate
pip install crcmod          # only luci_tls_client.py's CRC is inlined; crcmod optional
# luci_tls_client.py needs the extracted client cert/key beside it:
#   see docs/research/luci-metadata/client-certificate.md
```

Everything here is read-only against the devices. `luci_tls_client.py` intentionally
builds only zero-length GET-style frames; do not add SET/write frames until the
command semantics are confirmed.
