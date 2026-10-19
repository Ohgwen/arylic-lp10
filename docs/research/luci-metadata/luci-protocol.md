# LUCI "lucinetwork" protocol (TCP 7777, mutual TLS)

Reversed from `root/usr/bin/luciserver` + `usr/lib/libluci_helper.so` with radare2,
cross-checked against the Go Control app. All offsets are byte offsets into the
on-wire packet. The handshake is solved and the client is verified live — see
[handshake-solved.md](handshake-solved.md). This file documents the wire format.

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
# success: "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384"
```

## Packet frame

**10-byte header; payload starts at byte 10.** Confirmed by the deserializer
`handleCmdPacket` (`libluci_helper.so fcn @ 0x1dba0`): `memcpy(dst, pkt+0xa, Len)`
copies the payload from offset 10, and the header fields are read at:

| offset | size | field | notes |
| --- | --- | --- | --- |
| 0 | u16 LE | ID / RemoteID | 0 in our requests; echoed/assigned by server |
| 2 | u8 | Type | 0 in our requests; replies use 2 |
| 3 | u16 **LE** | **CmdID** | **the dispatch key** (see below). `3`=auth, `64`=UART tunnel |
| 5 | u8 | Status | 0 in our requests; auth-OK reply = `1`, NACK = `3` |
| 6 | u16 **LE** | **CRC** | CRC-16/XMODEM (see below) |
| 8 | u16 **LE** | **DataLen** | checked against max `0x1400`. *Replies write this **BE*** |
| 10.. | | payload | `DataLen` bytes |

The server's own log format strings name the six values
**ID, Command, Type, Status, CRC, Len** (recv: `RemoteID=%d Command=%d Type=%d
Status=%d CRC=%d Len=%d`). In practice the field at **offset 3** is what
`threadLoop` reads as the "CmdID" and dispatches on — this is the one that matters.

### Dispatch (luciserver `LuciClient::threadLoop`, `fcn @ 0x1faf0`)

```
CmdID = *(u16*)(buf+3)          ; little-endian; logged "CmdID: %d"
CmdID == 3  -> AuthenticateLuciClient(payload)   ; JSON Basic auth; see handshake-solved.md
CmdID == 4  -> second auth/unregister branch
else        -> if not authenticated (this+0xe0 == 0): writeNack()  (status=3)
               else route to the controller for that CmdID
                 CmdID 64 (0x40) -> LUCIUARTController (A31 MCU / AXX text commands)
```

### CRC

- **CRC-16/XMODEM** (poly `0x1021`, init `0x0000`), stored **little-endian at
  bytes [6:7]**, computed over the whole packet **with the CRC field (bytes 6–7)
  zeroed**.
- The deserializer reads it little-endian (`ldrh [r4,6]`) and compares to its own
  XMODEM. (An earlier scaffold wrote it big-endian; that failed CRC and produced
  the `status=3` reply that looked like a register NACK.)
- With **CRC == 0** the server **skips** validation (`cmp r8, 0` branch), so a
  zero-CRC frame is accepted without a correct checksum. Computing the real CRC is
  still the clean approach and what `luci_client.py` does.

## Authentication (CmdID 3) — the "handshake"

First frame after TLS must be CmdID 3 with JSON payload
`{"Authentication":"Basic","Value":"<base64(user:password)>"}`, credentials
`admin:Wireless` (device env `Defaultwebuser*`). Full derivation, the server
functions (`AuthenticateLuciClient fcn @ 0x1f688`, `writeNack fcn @ 0x1d820`), and
the credential source are in [handshake-solved.md](handshake-solved.md).

## Metadata channel (CmdID 64 — A31 MCU / UART tunnel)

After auth, tunnel MCU text commands on CmdID 64:
`MCU+VOL+GET&`, `MCU+SNG+INF&`, `MCU+PLM+GET&`, `MCU+PLP+GET&`, `MCU+INF+GET&`.
Replies come back as `AXX+...` frames (CmdID `0x7000`, type 2). The app parses them
in `package:a31_tcp_actions/src/receive/axx/*`. See handshake-solved.md.

The repo's local path (`LUCI_local -r 42`, MID 42 now-playing JSON parsed by
`luci.parse_now_playing`; MID 51 AirPlay play/pause) is the **Binder/IPC** channel
used on-device over ADB — a different transport from this network one.

## radare2 pointers

```
# luciserver:
pdf @ 0x1faf0     # LuciClient::threadLoop — recv/SSL_read, CmdID dispatch, the gate
pdf @ 0x1f688     # AuthenticateLuciClient — JSON Basic auth, env creds
pdf @ 0x1d820     # writeNack — the fixed status=3 reply
pdf @ 0x1d938     # serializer/packer (str 0x2fc99 "write() ID=…")
axt @ sym.imp.SSL_CTX_set_verify   # verify mode arg = 3 (mutual TLS mandatory)
# libluci_helper.so:
pdf @ 0x1dba0     # handleCmdPacket deserializer: header offsets + CRC check
pdf @ 0x195a8     # CRC-16/XMODEM thunk
```
