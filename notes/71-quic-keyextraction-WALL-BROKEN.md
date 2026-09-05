# 71 — QUIC key-extraction wall BROKEN → full get_seed wire decoded (x-argus=772 on-wire)

> User task: **"tôi tấn công tường trích-khóa-QUIC"** (attack the QUIC key-extraction wall).
> **STATUS: SOLVED.** The wire that note 70 declared "opaque (keys not captured)" is now fully
> decrypted end-to-end. get_seed request+response read in cleartext; genuine on-wire signature
> headers captured as ground truth. **Corrects note 70** on the transport host.

## 0. TL;DR
- **Plan A worked**: BoringSSL keylog callback → NSS keylog → offline QUIC 1-RTT derive → decrypt.
- 27 QUIC connections, **37/37 short-header packets decrypted both directions** (OK=37 failed=0).
- **get_seed rides a DEDICATED host** `mssdk22-normal-alisg.tiktokv.com` (34.107.238.235:443)
  over HTTP/3 — **note 70's "NO dedicated mssdk host / multiplexed on api22" was WRONG**
  (that verdict came from SNI-only analysis, before keys were extracted).
- **★ On-wire `x-argus` for get_seed = exactly 772 chars** → confirms the project "full-772" target.
- Pipeline proven **byte-exact**: `MD5(get_seed 131B body) == x-ss-stub` (32-hex).

## 1. The wall (recap from note 70)
get_seed transport = IETF QUIC (TLS 1.3, 1-RTT AEAD). Every exported plaintext surface was
eliminated (SSL_write/read on both BoringSSL builds, DNS, cronet C-API, system EVP_AEAD=0).
Kernel tcpdump captured the wire but the app-layer bytes were 1-RTT AEAD → opaque without the
TLS session secrets. Note 70 parked "read the plaintext wire" as a low-value sub-project.
The user chose to attack exactly that: extract the QUIC/TLS secrets.

## 2. Plan A — BoringSSL keylog extraction  (`scripts/keylog_frida.py`)
libttboringssl.so exposes the standard keylog hook. We arm it on every SSL_CTX:
- Hook `SSL_new(ctx)` → call `SSL_CTX_set_keylog_callback(ctx, cb)`.
- `cb(ssl, const char* line)` receives NSS-keylog-format lines
  (`CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>`, `SERVER_TRAFFIC_SECRET_0 ...`,
  `CLIENT_HANDSHAKE_TRAFFIC_SECRET ...`, `EXPORTER_SECRET ...`, etc).
- Offsets (build 45.5.4): **SSL_new = 0x32dc4**, **SSL_CTX_set_keylog_callback = 0x35890**
  (resolved by export name first, offset fallback second). Deferred install via
  android_dlopen_ext hook so it survives the lib loading late.
- **Frida-17 gotcha**: the static 2-arg `Module.findExportByName(lib,name)` was REMOVED.
  Use the instance method `m.findExportByName(name)`. Keep the `NativeCallback` in a global
  so GC does not free it under the native caller.
- The Python side prints only the *tag* of each line (secret redacted) to console and writes
  the raw keylog to `OUT` (git-ignored).

Result: 27 connections' traffic secrets extracted at will — the wall is a callback away.

## 3. Offline decoder  (`scripts/_quic_decode.py`, pure-python + pycryptodome + pylsqpack)
QUIC 1-RTT → HTTP/3 → QPACK, no external QUIC lib:
- Load keylog into `KL[client_random][label] = secret`.
- Per RFC 9001, from a traffic secret S: `key=HKDF-Expand-Label(S,"quic key",klen)`,
  `iv=...("quic iv",12)`, `hp=...("quic hp",klen)`; label prefix `"tls13 "`; hash chosen by
  secret length (32B→SHA256). CLIENT_TRAFFIC_SECRET_0 → c2s, SERVER_TRAFFIC_SECRET_0 → s2c.
- Header protection = AES-ECB(hp, sample@pn_off+4); short-header `fb ^= mask[0]&0x1f`.
  Nonce = iv XOR left-padded PN. AAD = plaintext header. AEAD = AES-128-GCM
  (TLS_AES_128_GCM_SHA256).
- **Key fix — zero-length client SCID**: client offers an empty SCID, so server→client short
  headers carry a **zero-length DCID**. c2s DCID = server's SCID, s2c DCID length = 0. The
  initial `and cli_scid` guard treated `b''` as falsy and bailed → all s2c failed. Fixed with
  `is not None` checks → OK=37 failed=0.
- STREAM frame parse + offset reassembly → HTTP/3 frames → QPACK via **pylsqpack** (the
  ls-qpack binding aioquic uses). Parse SETTINGS_QPACK_MAX_TABLE_CAPACITY; when the peer's
  control stream was not captured, fall back cap=65536 so dynamic-table header literals decode.
- Secrets are NEVER printed; per-stream bytes dumped to `decoded/` (git-ignored).

## 4. Capture artifacts (git-ignored — see §8)
- `ground-truth/getseed_wire/gs2.pcap` (7.99 MB) + `keylog2.txt` (22.4 KB) = matched pair.
- `decoded/*.bin` per-stream assembled bytes (regenerable).

## 5. get_seed ON THE WIRE  (redacted ground truth)
Host `mssdk22-normal-alisg.tiktokv.com` (34.107.238.235:443), HTTP/3, short_pkts=37.
Three mssdk POSTs share ONE connection (bidi streams 0/4/8):

| stream | :path            | body (content-length) |
|--------|------------------|-----------------------|
| 0      | `/ms/get_seed`   | 131 B                 |
| 4      | `/ms/dyn/task`   | 180 B                 |
| 8      | `/sdi/get_token` | 724 B                 |

**Request signature block — IDENTICAL lengths on all three** (values redacted to length):
```
:method POST ; :authority[32] ; :scheme https ; content-type application/octet-stream
x-ss-stub[32]      = MD5(body), hex          x-ss-req-ticket[13]   x-ss-dp[4]
x-argus[772]  *    x-gorgon[52]   x-ladon[48]   x-khronos[10]
user-agent[168]    accept-encoding[17]        x-tt-trace-id[55]
(x-tt-token, all cookie/sessionid  = REDACTED, never recorded)
```
→ signer header **lengths are endpoint-independent** (get_seed 131B and get_token 724B both
emit x-argus=772 / x-gorgon=52 / x-ladon=48 / x-khronos=10).

**get_seed request body (131 B) = mssdk protobuf**, on-wire hex head:
`08 <ver-varint> 10 02 18 04 22 <len> <encrypted blob ...>`
- field 1 = version/seq varint, field 2 = 0x02, field 3 = 0x04,
- **field 4 (tag 0x22) = the encrypted payload** (AEAD/opaque blob — same app-layer cipher
  as always; NOT plaintext just because TLS is peeled).

**get_seed response (stream 0 s2c, 217B hdrs + DATA 175+19):**
`:status ... ; content-type text/plain;charset=utf-8 ; content-encoding br` (brotli) then
protobuf/encrypted body — i.e. brotli-wrapped mssdk protobuf, field-4 encrypted.

## 6. Byte-exact validation
`MD5(get_seed 131B DATA body) == x-ss-stub value` → **True.**
Confirms: (a) our stream reassembly is exact, (b) x-ss-stub = MD5(request body) holds for
get_seed, (c) the whole QUIC→H3 pipeline is correct.

## 7. What this changes for the project
- **North-star length CONFIRMED on the wire**: genuine get_seed `x-argus` is **772** — the
  offline signer's "full-772" target is the real on-wire length, not an artifact. (See
  memory `offline-772-ceiling`.)
- **New ground truth for the offline signer diff**: we now have genuine, device-matched
  on-wire x-argus / x-gorgon / x-ladon / x-khronos / x-ss-stub for get_seed on THIS device —
  the exact thing to diff a forged signature against (length + structure; values stay in the
  git-ignored capture, never in notes).
- **Still opaque (unchanged, and fine)**: the get_seed app-layer *payload* (protobuf field 4)
  is mssdk-encrypted on the wire — but its plaintext is ALREADY in hand from the store-write
  hook (`getseed_fresh_ce0516_DECODED.json`, note 69). Peeling TLS did not (and did not need
  to) crack the inner app cipher.
- **Corrects note 70 verdict**: there IS a dedicated `mssdk22-normal-alisg.tiktokv.com` host
  for the mssdk/get_seed calls. Note 70's SNI-only "multiplexed on api22, no mssdk host" was a
  pre-key-extraction misread; a correction banner is added there.

## 8. SECURITY (hard rules honored)
- The decrypted stream exposes the user's LIVE session credentials in cleartext (cookies,
  sessionid, x-tt-token, msToken, BUYER_TOKEN, multi_sids, d_ticket, odin_tt). **None recorded**
  anywhere — notes/memory/git carry only lengths.
- `gs2.pcap`, `keylog2.txt`, `keylog*.txt`, `*.sslog`, `*.pcap*`, and `decoded/` are all
  git-ignored (added this session); `git ls-files ground-truth/getseed_wire/` = empty.
- No autonomous replay to production (replay = human decision, unchanged).
