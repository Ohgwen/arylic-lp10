# LUCI metadata over the LAN — research notes

Status: **in progress.** Authenticated LAN access to the LP10's metadata service
is solved; reading a now-playing register is blocked on one remaining step (a
register handshake, see [Remaining work](#remaining-work)).

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
- **Remaining:** the server NACKs data requests until the client sends a
  **register** packet first. The register `CommandType`/`appId` encoding is a Dart
  AOT constant in the app's `libapp.so` and still needs to be recovered.

## Documents

| File | What |
| --- | --- |
| [device-findings.md](device-findings.md) | Live probe results: ports, identity, UPnP, control port. |
| [firmware-analysis.md](firmware-analysis.md) | OTA server/URL, `.swu` structure, why adbd is absent. |
| [luci-protocol.md](luci-protocol.md) | The LUCI 7777 TLS protocol: header, CRC, field offsets, evidence. |
| [client-certificate.md](client-certificate.md) | Where the client cert/key came from and how to re-extract. |
| [remaining-work.md](remaining-work.md) | Exactly what's left, with pointers into the binaries. |

## Tools

Reusable scripts are in [`tools/research/`](../../../tools/research/):

- `lp10_probe.py` — identity + control-port status + port scan (read-only).
- `upnp_nowplaying.py` — SSDP-discover the renderer and read AVTransport/RenderingControl.
- `luci_tls_client.py` — open a mutual-TLS session to 7777 with the client cert,
  build XMODEM-CRC LUCI frames, and send/receive. This is the scaffold to finish
  the register handshake on.

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
