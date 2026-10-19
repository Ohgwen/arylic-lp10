# LUCI "lucinetwork" protocol (TCP 7777, mutual TLS)

Reversed from `root/usr/bin/luciserver` with radare2, cross-checked against the
Go Control app's Dart package `libre_luci_actions`. All offsets are byte offsets
into the on-wire packet.

## Transport

- **TCP 7777**, **TLS (mutual)**. Confirmed via the bind site in `luciserver`:
  the sockaddr constant `0x611e0002` → family `0x0002` (AF_INET), port bytes
  `1e 61` = **7777**.
- Server presents a chain `LWT Root CA` → device cert
  (`CN=LibreLS8ARYLLP10 …`). It sends a TLS **CertificateRequest** and
  `SSL_CTX_set_verify` is called with mode **3**
  (`SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`), so a **client certificate
  is mandatory**. Without one the handshake aborts with alert 40.
- The client cert must chain to `LibreCA.pem`. See
  [client-certificate.md](client-certificate.md).

Verify the handshake:

```sh
echo | openssl s_client -connect <ip>:7777 -cert client.pem -key client.key -tls1_2
# success: "SSL handshake has read ... New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384"
```

## Packet frame

**10-byte header; payload starts at byte 10.** Confirmed by the deserializer
`fcn.0001dba0` in `luciserver`:
`memcpy(dst, pkt + 0xa, Len)` copies the payload from offset 10, and the header
fields are read at these offsets:

| offset | size | field | notes |
| --- | --- | --- | --- |
| 0 | u16 | (Command/Type/Status group) | one of Command/Type/Status; exact split TBD |
| 2 | u8  | (Command/Type/Status group) | |
| 3 | u16 **big-endian** | **ID / MID** | serializer writes it with `rev16` (byte-swapped) at [3] |
| 5 | u8  | (Command/Type/Status group) | read first & stored prominently; likely Command or Status |
| 6 | u16 **big-endian** | **CRC** | CRC-16/XMODEM, see below |
| 8 | u16 | **DataLen** | checked against max `0x1400` (MID_LENGTH_MAX) |
| 10.. | | **payload** | `DataLen` bytes |

The server's own field order, from its log format strings:

- send: `ID=%d Command=%d Type=%d Status=%d DataLen=%d mCRC=%d SocketInfo=%d`
- recv: `RemoteID=%d Command=%d Type=%d Status=%d CRC=%d Len=%d`

So the six header values are **ID, Command, Type, Status, CRC, Len**. We confirmed
ID=offset 3 (BE), CRC=offset 6, Len=offset 8. Command/Type/Status occupy offsets
{0 (u16), 2 (u8), 5 (u8)} — the precise assignment among those three is the main
open detail (see remaining-work.md). `ID` is believed to be the MID (e.g. 42).

### CRC

- **CRC-16/XMODEM** (poly `0x1021`, init `0x0000`), stored **big-endian at bytes
  [6:7]**, computed over the packet **with the CRC field (bytes 6–7) zeroed**.
- Determined by brute-forcing CRC variants against the server's own reply (its CRC
  matched XMODEM over `header[0:6] + 00 00 + header[8:10]`).
- The deserializer **skips** CRC validation when the CRC field is 0 **and** a device
  flag at `[obj+0x169]` is 0 (`cmp r8,0; … cmp [r6+0x169],0`). On the tested units
  that skip did not help (requests still NACK), so compute the real CRC.

## MID 42 = now-playing

`LUCI_local -r 42` returns text containing `Data: { … "Window CONTENTS": { … } }`
with (parsed by the repo's `luci.parse_now_playing`):
`TrackName, Artist, Album, CoverArtUrl, Mime, SampleRate, BitDepth, TotalTime,
Current Source, PlayState`. `PlayState == 0` means playing. MID 51 carries
play/pause for the AirPlay source.

## Current blocker: must register first

Zero-length read frames (any command byte, valid or zero CRC) all get the same
fixed 10-byte reply `00 00 02 00 00 03 d2 10 00 00` — a NACK. The Go Control app
(`libre_luci_actions`) shows the client must **register** before data requests:
`send/register.dart` → `receive/register_ack.dart`, log
`": connected and registered successfully"`, then actions like
`get_play_info_action`. See [remaining-work.md](remaining-work.md).

## radare2 pointers (in `luciserver`)

```
# bind site / port:
aaaa; axt @ sym.imp.bind      # -> fcn.0001cfcc, bind @ 0x1d074; pool const 0x611e0002
# receive/parse path:
pdf @ fcn.0001faf0            # recv/SSL_read into a 0x1400 buffer
pdf @ fcn.0001dba0            # deserializer: header offsets + CRC check (str 0x2fe5f)
pdf @ fcn.0001d938            # serializer/packer (str 0x2fc99 "write() ID=…")
# CRC thunk:
pdf @ fcn.000195a8           # tiny thunk to the real CRC-16/XMODEM routine
# TLS verify mode:
axt @ sym.imp.SSL_CTX_set_verify   # -> fcn.0001d0bc, mode arg = 3
```
