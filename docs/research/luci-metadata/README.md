# LUCI metadata over the LAN — research notes

Status: **handshake solved.** Authenticated, two-way LAN access to the LP10's
metadata service works end-to-end on ADB-less firmware (verified live on both
players). The one open item is capturing populated metadata values from a device
that is actively playing — see [handshake-solved.md](handshake-solved.md) and
[remaining-work.md](remaining-work.md).

This directory records the reverse-engineering done to find a way to read
now-playing metadata (track title/artist/album/artwork, playback state) on LP10
firmware that has **no ADB** — the channel the existing Detailed profile relies
on. Everything here was done read-only against the devices; nothing on a player
was modified.

## TL;DR

- The tested players run firmware **`AR241CP_8747.29.2`**, which **does not ship
  `/usr/bin/adbd`**. TCP/5555 is closed, so the repo's ADB-based metadata path
  and the `remote_close` repair cannot work on this firmware at all.
- Control (port 2018) and UPnP (the renderer on a high port, e.g. 49494) work and
  give **source, volume, mute, play/stop state, device name**. UPnP does **not**
  carry track metadata for `NET`/streaming sources (reports `STOPPED`).
- The on-device now-playing data lives in **LUCI register (MID) 42**, served by
  `luciserver`. Locally it's Android **Binder** IPC; `LUCI_local -r 42` reads it
  (that's what the ADB path ran on-device).
- Over the LAN the same data is exposed by `luciserver`'s **"lucinetwork"** service
  on **TCP 7777**, behind **mutual TLS**. It requires a **client certificate**
  signed by the Libre Wireless (LWT) Root CA.
- **That client certificate + key were extracted from the Go Control app** and
  **authenticate successfully to both players** on 7777.
- The LUCI packet frame was reversed: **10-byte header, CRC-16/XMODEM**, payload
  from byte 10. See [luci-protocol.md](luci-protocol.md).
- **Handshake (solved):** the first frame must authenticate on **CmdID 3** with
  `{"Authentication":"Basic","Value":base64("admin:Wireless")}`. After that,
  metadata is read by tunnelling **A31 MCU** commands (`MCU+...+GET&`) on **CmdID
  64** and parsing the `AXX+...` replies. There was no Dart `appId` secret — it is
  plain HTTP Basic auth. See [handshake-solved.md](handshake-solved.md).
- **Open:** capture populated values (volume/track) from a *playing* device; then
  wire a LUCI-over-TLS transport into the integration. See
  [remaining-work.md](remaining-work.md).

## Documents

| File | What |
| --- | --- |
| [device-findings.md](device-findings.md) | Live probe results: ports, identity, UPnP, control port. |
| [firmware-analysis.md](firmware-analysis.md) | OTA server/URL, `.swu` structure, why adbd is absent. |
| [luci-protocol.md](luci-protocol.md) | The LUCI 7777 TLS protocol: header, CRC, field offsets, dispatch. |
| [handshake-solved.md](handshake-solved.md) | **The solved auth handshake + MCU metadata channel, with live evidence.** |
| [client-certificate.md](client-certificate.md) | Where the client cert/key came from and how to re-extract. |
| [remaining-work.md](remaining-work.md) | Exactly what's left, with pointers into the binaries. |

## Tools

Reusable scripts are in [`tools/research/`](../../../tools/research/):

- `lp10_probe.py` — identity + control-port status + port scan (read-only).
- `upnp_nowplaying.py` — SSDP-discover the renderer and read AVTransport/RenderingControl.
- `luci_client.py` — **the working authenticated client**: mutual-TLS + Basic
  auth on CmdID 3 + MCU query tunnel on CmdID 64 + frame parser. Verified live.
- `luci_tls_client.py` — the earlier low-level TLS/frame scaffold (kept for
  reference; `luci_client.py` supersedes it).

## Environment used

- Host: Linux, `adb` (platform-tools 34), `radare2` 6.0.7, Python 3 + `capstone`,
  `pyelftools`, `crcmod`, `openssl`.
- Devices (on a trusted LAN): `10.200.10.2` (Fireplace), `10.200.10.3` (Kitchen).
  Substitute your own IPs.
- Firmware image analyzed: `lp10_AR241CP_8747_29_6701c857.swu`
  (sha256 `6701c857dd66d10f151f1058dd061c643a3cbf16b4cf6cef7ab31ceb38baa132`).
- App analyzed: `Go+Control_2.2.3_APKPure.xapk`.

## Safety / scope

- All device interaction was read-only. No player filesystem or config was changed.
- The LUCI write path exists (MIDs can be *set*). Any future client work must send
  only read/GET requests and keep `DataLen = 0` until the command semantics are
  fully confirmed.
- The services are unauthenticated-by-design on the LAN except 7777 (mutual TLS).
  Keep this on a trusted network.
