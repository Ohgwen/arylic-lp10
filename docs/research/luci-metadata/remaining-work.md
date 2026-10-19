# Remaining work

Goal: read now-playing / volume / source over the authenticated 7777 channel on
firmware without ADB, and expose it to the integration.

## Solved

The handshake blocker from the first pass is **done** — see
[handshake-solved.md](handshake-solved.md). In short:

- Mutual-TLS connect with the bundled client cert.
- Authenticate on **CmdID 3** with `{"Authentication":"Basic","Value":
  base64("admin:Wireless")}`. Reply status byte `1` = OK.
- Tunnel **A31 MCU** text commands on **CmdID 64**; read `AXX+...` replies.

`tools/research/luci_client.py` implements and verifies all of this live against
both players. There was no Dart `appId`/register secret — that earlier guess was
wrong; it is plain Basic auth.

## Open: capture populated metadata values

The transport, auth, framing and MCU tunnel are proven, but during testing **both
players were STOPPED** (idle NET source), so the value-bearing replies were not yet
captured. Still to confirm, ideally with a device actively playing:

1. The exact `AXX+VOL+<n>` reply to `MCU+VOL+GET&` (ground-truth volume is also
   visible via UPnP `GetVolume`, so cross-check there).
2. The `AXX+SNG+INF` now-playing reply shape (title/artist/album/duration/pos) and
   `AXX+PLY`/`AXX+PLP`/`AXX+PLM` for state/position/mode. The field grammar is in
   the app: `package:a31_tcp_actions/src/receive/axx/axx_*.dart` — decode those
   (strings are readable in `libapp.so`; numeric bits need Blutter) or just capture
   live and read the ASCII.
3. Whether values arrive synchronously after the `MCU+...+GET&` or only as async
   pushes on change. On connect the UART controller streams a capability list
   (`SRC;/VOL;/MUT;…/VER;` each + `SUCCESS`) which is **not** the values.

## Then: wire it into the integration

- Add a LUCI-over-TLS transport (7777 + bundled client cert) selected when `adbd`
  is absent, as an alternative to the ADB path.
- Map `AXX+...` fields to the same now-playing shape the repo's
  `luci.parse_now_playing` produces, so the coordinator/entities are unchanged.
- Keep it **read-only**: only `MCU+...+GET&`/`+INF&`. Do not send MCU SET commands
  (e.g. `MCU+VOL+<n>&`) until each is understood and intentionally supported.

## Cert handling for a shipped integration

Bundling a shared app-derived client cert has obvious caveats (it's the Go Control
app's cert; it could be rotated/revoked by a firmware update). Document clearly,
keep LAN-only, and consider making the cert path user-configurable. The private key
is **not** committed here — re-extract per [client-certificate.md](client-certificate.md).

## Quick restart checklist

1. Re-extract `client.pem`/`client.key` (client-certificate.md) beside the tool.
2. `python tools/research/luci_client.py --host <ip> --auth-only` → expect
   `AUTH OK as 'admin'`.
3. Start playback on that device, then
   `python tools/research/luci_client.py --host <ip> --query 'MCU+SNG+INF&'
   --query 'MCU+VOL+GET&' --listen 5` and read the `AXX+...` frames.
4. Map fields → integration transport.
