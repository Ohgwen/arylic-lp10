# The 7777 handshake — SOLVED

The blocker described in the first research pass ("the server NACKs every data
request until the connection registers") is resolved. There was **no Dart-snapshot
secret to recover**: the "register" is ordinary **HTTP Basic authentication wrapped
in JSON**, sent as the first frame on a dedicated CmdID. This was derived from the
firmware (`luciserver`) and confirmed live against both players.

## TL;DR — how to read the device over the LAN, no ADB

1. Open a mutual-TLS socket to `tcp/<ip>:7777` with the bundled client cert/key.
2. Send one **auth frame** on **CmdID 3** whose payload is:
   ```json
   {"Authentication":"Basic","Value":"<base64(user:password)>"}
   ```
   with `user=admin`, `password=Wireless` (see "Credentials" below).
   The server replies with a frame whose **status byte (offset 5) == 1** = OK
   (`00 00 02 00 03 01 27 ac 00 00`). A NACK has status `3`.
3. On the **same socket**, tunnel **A31 MCU** text commands on **CmdID 64** (the
   UART controller). Requests are `MCU+...+GET&`; replies come back as `AXX+...`
   frames.

`tools/research/luci_client.py` implements exactly this and is verified working.

## Why the first attempts all NACK'd

Three independent bugs/misconceptions, each fixed:

1. **CRC byte order.** The server reads the CRC little-endian at `[6:8]` and
   compares it to its own XMODEM over the frame-with-CRC-zeroed. The scaffold wrote
   it big-endian, so every frame failed CRC and got the generic `status=3` reply —
   which looked like a "register NACK" but was a CRC-mismatch reply. Fix: write CRC
   **little-endian**. (With `CRC==0` the server skips the check entirely — see the
   `cmp r8, 0` branch in `handleCmdPacket` — which is why zero-CRC frames behaved
   differently.)
2. **Dispatch key.** `luciserver`'s `LuciClient::threadLoop` reads a 16-bit
   **CmdID at wire offset 3** (`ldrh [sp,0xcb]`, the "CmdID" in its own log) and
   branches on it *before* any MID routing:
   ```
   cmp CmdID, 3  -> AuthenticateLuciClient   (the register/auth path)
   cmp CmdID, 4  -> (de)register path
   else          -> require registered flag [this+0xe0]; if 0 -> writeNack()
   ```
   So auth MUST be sent on CmdID 3. Sending the auth JSON on any other CmdID is
   ignored and NACK'd, which is what happened in the first live tests.
3. **Payload shape.** The auth path parses the payload as JSON
   (`Json::CharReaderBuilder`), requires `Authentication == "Basic"`, base64-decodes
   `Value`, and compares to `user:password`. An empty or non-JSON payload fails to
   parse and NACKs.

## The server side (ground truth)

`luciserver` `LUCINetworkController::LuciClient::threadLoop` (`fcn @ 0x1faf0`):

```
recv/SSL_read -> CmdID = *(u16*)(buf+3)            ; logged "CmdID: %d"
if CmdID == 3:  AuthenticateLuciClient(this, payload)   ; fcn @ 0x1f688
                on success: set this->registered (byte @ +0xe0) = 1
                            log "authentication successfull - hash matched.
                                 Registering client %s"
                on failure: writeNack()                 ; fcn @ 0x1d820
if CmdID == 4:  ... (second auth/unregister branch, also gated)
else:           if this->registered == 0:  writeNack()  ; -> status=3 reply
                else:                        route to controller (fcn @ 0x1c670)
```

`AuthenticateLuciClient` (`fcn @ 0x1f688`):

```
parse payload as JSON (log tag "AuthenticateLuciClient";
                       error -> "Failed to parse user credential Json")
require  json["Authentication"] == "Basic"           ; str "Basic"
take     json["Value"]                                ; base64 of user:password
user  = GetEnvItemByName(kNewWebUserName)  or kDefaultWebUserName
pass  = GetEnvItemByName(kNewWebUserPassword) or kDefaultWebUserPassword
compare decoded Value against user:pass  -> match => authenticated
```

`writeNack()` (`fcn @ 0x1d820`, called from the three gated sites in `threadLoop`)
emits the fixed `00 00 02 00 00 03 d2 10 00 00` reply (type 2, status 3).

## Credentials

From the device env dump (`log.txt`, same `GetEnvItemByName` store the firmware
reads):

```
Newwebusername      : (empty)      Defaultwebusername     : admin
Newwebuserpassword  : (empty)      Defaultwebuserpassword : Wireless
luciclientverification : true
```

`New*` are empty, so the firmware falls back to `Default*`:
**`admin` / `Wireless`** → `Value = base64("admin:Wireless") = YWRtaW46V2lyZWxlc3M=`.
If a device had its web credentials changed, `Newwebuser*` would hold them and the
client must use those instead.

## The UART / A31 MCU channel (CmdID 64)

The real device metadata (volume, source, mute, EQ, play state, song info) lives on
the **MCU**, reached by tunneling **A31 MCU text commands** through CmdID 64
(`LUCIUARTController`, `WriteTunnelDataToUart`; the server log calls it
"message alert for MID 64 from UART side").

- **Request** (client → device): `MCU+<P>+<OP>&`, e.g. `MCU+VOL+GET&`,
  `MCU+INF+GET&`, `MCU+PLM+GET&`, `MCU+PLP+GET&`, `MCU+SNG+INF&`.
- **Reply/push** (device → client): `AXX+<P>+<value>` frames. The Go Control app
  parses these in `package:a31_tcp_actions/src/receive/axx/` —
  `axx_sng_inf.dart` (now-playing), `axx_vol.dart` (volume), `axx_ply.dart`
  (play state), `axx_plm.dart` (mode), `axx_plp.dart` (position), etc.

### Observed so far

On connect the UART controller streams a capability/handshake list — paired frames
`"SRC;"`,`"SUCCESS"`,`"VOL;"`,`"SUCCESS"`,`"MUT;" … "VER;"`,`"SUCCESS"` (CmdID
`0x7000`, type 2). Both players were **STOPPED** (NET source idle) during testing,
so no live `AXX+SNG+INF` track payload or `AXX+VOL+<n>` value was captured yet. The
transport, auth, framing and MCU tunnel are all proven; capturing populated values
just needs a device that is actively playing (or a state change to trigger the
push). This is the one open empirical item — see remaining-work.md.

### Frame length asymmetry (important for parsers)

Requests we build use **little-endian** `DataLen` at `[8:10]` (matches
`handleCmdPacket`). The device's **replies/pushes write `DataLen` big-endian**.
`luci_client.parse_frames()` handles this by trying LE then falling back to BE.
