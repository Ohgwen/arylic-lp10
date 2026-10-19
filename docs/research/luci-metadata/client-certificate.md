# The LUCI client certificate

The mutual-TLS service on 7777 requires a client certificate chaining to the
**LWT Root CA**. The Go Control app ships one (a shared, hardcoded app credential —
not per-device), and it authenticates to the players.

## Source

Inside `Go+Control_2.2.3_APKPure.xapk`:

```
<xapk>
  uni.UNI123F50F.apk                 # base APK (Flutter/uni-app)
    assets/flutter_assets/assets/cert/client.pem   # <-- client certificate
    assets/flutter_assets/assets/cert/client.key   # <-- matching private key (RSA 2048)
```

(The app also carries unrelated certs: `release_ca/*` is a "Feedback Ticket Test
Env" CA, and `packages/upnp_services/assets/certs/certificate_axx.p12`. Ignore those.)

## Identity

```
client.pem
  subject: CN=LibreLS10RAKOIT RKLIBRLS101424000001 21,
           O=Libre Wireless Technologies, OU=Libre Wireless RD, ST=KA, L=Bengaluru, C=IN
  issuer:  CN=LWT Root CA, O=Libre Wirless Technologies, ...   (matches firmware LibreCA.pem)
  serial:  15D37B52908810F1FF8EE6364C3ADF2223B2A2C7
  sha256 fingerprint:
           AB:D8:EB:6C:F2:92:BA:16:D9:50:DA:5E:38:F3:4D:35:ED:02:F8:F0:62:0B:84:EF:72:62:89:CC:85:11:01:75
  validity: 2024-04-02 .. 2044-03-28
client.key  = RSA 2048, matches client.pem (proven by live handshake)
```

Verified: `openssl verify -CAfile <firmware>/etc/ssl/certs/LibreCA.pem client.pem` → OK,
and mutual-TLS handshakes to both players on 7777 succeed.

## Re-extracting (one-off)

```sh
mkdir -p gc && cd gc
unzip -o ../Go+Control_2.2.3_APKPure.xapk uni.UNI123F50F.apk
unzip -o uni.UNI123F50F.apk \
  'assets/flutter_assets/assets/cert/client.pem' \
  'assets/flutter_assets/assets/cert/client.key'
cp assets/flutter_assets/assets/cert/client.* .
```

Then point `tools/research/luci_tls_client.py` at `client.pem` / `client.key`.

## Why the key isn't committed here

`client.pem` (the public certificate) is committed next to this doc. The matching
**private key is deliberately not committed** — it's a private key and this is a
public repo (secret scanners will flag it, and it's poor hygiene even for a
shared/extractable credential). It's trivially re-extracted from the APK with the
commands above. Keep `client.key` out of git (`.gitignore` covers `*.key` under
this folder).
