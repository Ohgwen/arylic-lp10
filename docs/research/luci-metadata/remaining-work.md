# Remaining work

Goal: read now-playing (MID 42) over the authenticated 7777 channel and expose it
to the integration on firmware without ADB.

## The one blocker: the register handshake

The server NACKs every data request (`00 00 02 00 00 03 d2 10 00 00`) until the
connection **registers**. The Go Control app's `libre_luci_actions` package does:

```
send/register.dart   ->   receive/register_ack.dart
# then: get_play_info_action, get_info, get_version, preset/*, etc.
```

and logs `": connected and registered successfully"`. `LuciRegisterInfo(appId: …)`
is the payload. So the first packet after TLS connect must be a **register** packet.

### What needs recovering

1. The **register packet**: its `Command`/`Type` byte value(s), and the `appId`
   payload (likely a small JSON or string the app generates — see
   `LuciRegisterInfo`, `_createRandomId`, `registerDevice` in the Dart snapshot).
2. The **Command/Type/Status byte assignment** among header offsets {0, 2, 5}
   (luci-protocol.md pins ID@3, CRC@6, Len@8 but not which of the remaining three
   is Command vs Type vs Status).
3. The **GET value** and how a MID is requested (register-for-MID vs one-shot GET).
   `get_play_info_action` is the request that yields MID 42's JSON.

### Where to get it

- **Dart AOT snapshot** `ex_config.armeabi_v7a/lib/armeabi-v7a/libapp.so` contains
  the encoder `LibreSendMsgEncoder` and the `libre_luci_actions` logic. Identifier
  strings are present (grep worked), but the numeric constants are in compiled
  Dart. Tools: Blutter (Dart AOT → C++/pseudocode), or `darter`/`doldrums` for the
  snapshot, then read `register.dart` / `get_play_info_action.dart` encoders.
- **Dynamic capture (easiest)**: run Go Control against a player and capture the
  7777 TLS. Because you hold the client key, you can MITM with `mitmproxy`/`socat`
  + the extracted `client.pem`/`client.key` and the server cert, or patch the app
  to log plaintext frames. One real register+get_play_info exchange gives the exact
  bytes to replay.
- **Firmware side**: `luciserver`'s `handleCmdPacket` dispatch and the register
  handler show which Command/Type the server expects and what a register must
  contain. Start from `fcn.0001dba0` (deserializer) → the handler it calls, and
  search for the register/"REGISTER MID" path (`libluci_helper.so` has
  `REGISTER MID FAIL`).

## After the handshake works

- Read MID 42, parse the `Window CONTENTS` JSON exactly like the repo's
  `luci.parse_now_playing` (reuse that parser; only the transport changes).
- MID 51 for AirPlay play/pause, as the repo already does.
- Then: add a transport in the integration that uses LUCI-over-TLS (7777 + bundled
  client cert) as an alternative to ADB, selected when adbd is absent. Keep it
  read-only (GET, `DataLen = 0`); never send SET frames.

## Nice-to-haves / loose ends

- Confirm whether the `[obj+0x169]` flag (CRC-skip gate) is ever 0 in practice; if
  so, CRC can be sent as 0.
- Identify what port 9090 actually is (dynamically bound; not needed for metadata).
- Decide cert handling for a shipped integration (bundling a shared app cert has
  obvious caveats; document clearly and keep it LAN-only).

## Quick restart checklist

1. Re-extract `client.pem`/`client.key` (client-certificate.md).
2. `python tools/research/luci_tls_client.py --host <ip> --handshake` → confirm TLS.
3. Implement register in that script (the gap above), then `--read-mid 42`.
4. Parse JSON → done.
