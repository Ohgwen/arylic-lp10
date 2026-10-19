# Firmware analysis

## OTA server and manual download

The device env (`fwdownload_xml`) points at:

```
https://lp10.arylic.rakoit-ota.com/v1
```

This endpoint is a JSON POST API, not a file server. It names the missing fields
in its error responses. A working request:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{"device":{"brand":"Arylic","deviceId":"<12-hex-id>","fwVersion":"AR241CP_8747.29.2","model":"LP10"}}' \
  https://lp10.arylic.rakoit-ota.com/v1
```

Response:

```json
{"errorCode":1000,"errorString":"SUCCESS",
 "url":"https://cdn.rakoit-ota.com/lp10/lp10_AR241CP_8747_29_6701c857.swu",
 "version":"AR241CP_8747","otapackage":"...","mcuOnlyUpdate":false}
```

Notes:
- The server only ever returns the **current** build. Older `fwVersion` values
  return the same file or `{"errorCode":1001,"errorString":"No update available"}`.
- The filename's hex suffix is the **first 8 hex of the file's SHA-256**
  (`lp10_AR241CP_8747_29_`**`6701c857`**`.swu`), so older filenames can't be guessed.
- The CDN directory is not listable (404).
- The endpoint appeared to rate-limit / dedupe by device id during testing — be
  gentle; it's the same server your players use for real update checks.

Downloaded file:
`lp10_AR241CP_8747_29_6701c857.swu`, 89,527,296 bytes,
sha256 `6701c857dd66d10f151f1058dd061c643a3cbf16b4cf6cef7ab31ceb38baa132`.

### Finding older firmware

Not solved. The OTA API won't serve it and the CDN isn't listable. Options:
Arylic support / forum (ask for `AR241CE_8530.23.2` by name), capture the download
URL from a player still on old firmware before it updates, or the Wayback Machine
(`cdn.rakoit-ota.com/lp10/*`).

## `.swu` structure

A SWUpdate package (cpio SVR4-CRC). Outer archive contains one inner `software.swu`,
which contains:

```
sw-description          # SWUpdate manifest (plaintext, lists images + sha256)
sw-description.sig
boot.img.encrypt        # encrypted
dtb.img.encrypt         # encrypted
rootfs.squashfs         # NOT encrypted — mountable with unsquashfs
factory_customer.squashfs
mcu.bin
update.sh
```

Extract:

```sh
mkdir a && (cd a && cpio -idm --no-absolute-filenames < ../lp10_*.swu)   # -> software.swu
mkdir b && (cd b && cpio -idm --no-absolute-filenames < ../a/software.swu)
unsquashfs -d root b/rootfs.squashfs
unsquashfs -d fc  b/factory_customer.squashfs
```

`sw-description` reports `fwversion = "AR241CP_8747"`, `mcuversion = "29"`.

## adbd is absent — why TCP/5555 is dead

- `root/usr/bin/adbd` **does not exist** in the rootfs.
- `root/etc/init.d/S89usbgadget` still references `/usr/bin/adbd &` (and network
  adb init), but the binary isn't there, so nothing ever listens on 5555.
- Consequence: the repo's Detailed-profile metadata (ADB → `LUCI_local`) and the
  `remote_close` repair (patching `adbd`) are **inoperable** on this firmware. The
  repair's exact-hash check would also refuse this build regardless.

## Key binaries (paths inside `root/`)

| Path | Role |
| --- | --- |
| `usr/bin/luciserver` | LUCI server. Binds TCP **7777** ("lucinetwork", mutual TLS) and a local command socket. Owns register 42 via Binder. |
| `usr/bin/yaniserver` | YANI companion to LUCI. |
| `usr/bin/LUCI_local` | CLI that reads/writes MIDs locally (`-r <MID>`, `-a`). Talks Binder via `libluci_helper.so`. |
| `usr/lib/libluci_helper.so` | `android::LUCIHelper` — Binder proxy (`BpLuciTransport`). Local IPC, not network. |
| `usr/bin/messageboxhandler` | Fetches track metadata via curl; also runs a config-port "TCP-TUNNEL" server. |
| `usr/bin/librewebserver` | Port 80 httpapi host (httpapi disabled here). |
| `etc/ssl/certs/LibreCA.pem` | The LWT Root CA (public). Client certs must chain to this. |
| `etc/web/description.xml` | UPnP MediaRenderer description. |

The per-device LUCI server key lives at `/factory/libre/luci/deviceCert.pem` +
a "unified key" — on the device's `/factory/libre` partition, **not** in the OTA
image (only `/factory/custom` ships as `factory_customer.squashfs`).
