# Device findings (live probes)

Read-only probes against two LP10 players on a trusted LAN. Replace IPs with yours.

## Identity

Both players identify over UDP 1800 (the repo's `discovery_metadata`) as:

| Field | 10.200.10.2 | 10.200.10.3 |
| --- | --- | --- |
| name | Fireplace | Kitchen |
| identity (USN) | `d8f71071384c` | `d8f710712f18` |
| model | LP10 | LP10 |
| software_version | `AR241CP_8747.29.2` | `AR241CP_8747.29.2` |
| connectivity | Ethernet | Ethernet |

Firmware `AR241CP_8747.29.2` is **not** the `AR241CE_8530.23.2` build the repo's
ADB repair targets. It is a different branch.

## Open ports

```
80    open   librewebserver (Linkplay httpapi host — but httpapi is disabled, see below)
2018  open   control port (repo's LP10Client)
5555  CLOSED  ADB — adbd is not present in this firmware (see firmware-analysis.md)
7777  open   luciserver "lucinetwork" — mutual-TLS LUCI (metadata!). See luci-protocol.md
9090  open   dynamically-bound service (not the metadata channel; red herring)
49494 open   UPnP MediaRenderer (LibreDMR). Port is per-boot; discover via SSDP.
```

`adb connect <ip>:5555` → `Connection refused` on both.

## Control port (TCP 2018) — works

The repo's `LP10Client.query_status()` works and returns, e.g. for Kitchen while
playing a NET source:

```
source: NET, volume: 20, muted: false, treble/mid/bass/balance: 0,
max_volume: 100, deep_bass: false, eq_preset: 0, display_on: true
```

This is the authoritative source for **source / volume / mute / tone / EQ**.

## UPnP MediaRenderer — works for state, not for NET track metadata

- SSDP (`M-SEARCH`, UDP 1900) → `LOCATION: http://<ip>:49494/description.xml`,
  `Server: .../Portable SDK for UPnP devices/1.6.25`.
- Control URLs (from the live description, they differ from the sample XML):
  - AVTransport: `/upnp/control/rendertransport1`
  - RenderingControl: `/upnp/control/rendercontrol1`
- `GetVolume` / `GetMute` / `GetTransportInfo` all return live values.
- **But** when a `NET`/streaming/AirPlay source is playing, AVTransport reports
  `CurrentTransportState = STOPPED`, `NrTracks = 0`, empty `TrackMetaData`. So the
  renderer only reflects DLNA-pushed playback, not streaming sources. This matches
  the README's "AirPlay shows Idle" note.

See `tools/research/upnp_nowplaying.py`.

## Linkplay HTTP API — disabled on this firmware

`http://<ip>/httpapi.asp?command=getPlayerStatus` (and `getStatusEx`) returns:

```
Access Error: Not Found
Cannot stat /factory/custom/web/httpapi.asp
```

The command handler isn't registered; the server treats `httpapi.asp` as a static
file that doesn't exist. So the usual Linkplay `getPlayerStatus` metadata route is
not available here.

## Conclusion

The only source of real now-playing metadata for a NET source on this firmware is
LUCI register 42, reachable on the LAN only via the mutual-TLS 7777 service.
