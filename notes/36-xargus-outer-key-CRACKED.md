# 36 — X-Argus OUTER key (Android) — CRACKED + VERIFIED (2026-08-24)

> Mục tiêu (note 31 §"Còn lại"): "OUTER AES key/IV Android chưa có → chưa decrypt được report".
> **ĐÃ GIẢI.** OUTER = **AES-128-CBC chuẩn**, key/iv = md5 hai nửa của một **SIGN_KEY build-constant**.
> Verified offline trong unidbg harness (enc==ct, dec==PT) **và** trên **13/13 mẫu X-Argus genuine device**.
> Decoder: `huongB_devirt19/xargus_outer.py` (self-test PASS). Nối [[30-xargus-inner-report-decoded]], [[33-hash19-pskcalhash-SOLVED]].

## Công thức OUTER (build musically 45.5.4, `libmetasec_ov.so` md5 `02f47578`)
```
X-Argus = base64( rb01[2B] || AES-128-CBC-enc(plaintext, aes_key, aes_iv) )
  aes_key = md5(SIGN_KEY[:16]) = 8252970d959b06db102e17d85c0ec1af
  aes_iv  = md5(SIGN_KEY[16:]) = 4d207ea37a419f7d622f81c6a2f53594
  SIGN_KEY = c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163   (BUILD CONSTANT)
```
- **plaintext KHÔNG pkcs7** — block-aligned sẵn (đây là lý do `decode_xargus` cộng đồng 2020, vốn `pkcs7_unpad`, **reject** mẫu modern → nhầm là "sai key / thuật toán đổi").
- plaintext = header 9B (`byte0=0xec`, `byte5=0x01`, `byte8=0x18` cố định) + inner body (tầng Simon/reverse-XOR — **chưa** decode ở đây; đó là tầng INNER, ngoài phạm vi "OUTER key").
- **SIGN_KEY = chính PSK material `c02f250f…`** của note 33 (§33.2 unidbg tái tạo bit-exact từ license). ⇒ cùng key material nuôi cả slot16/#19 lẫn OUTER argus.

## SIGN_KEY = BUILD-CONSTANT (không per-device) — bằng chứng
Decrypt **13 mẫu genuine** (từ device THẬT khác device forge của harness) bằng key trên → **cả 13** ra header `byte0=0xec, byte5=0x01, byte8=0x18`. Wrong-key cho random đều → xác suất 13/13 trùng `0xec` ≈ 0. ⇒ SIGN_KEY chỉ phụ thuộc **license (build)**, KHÔNG phụ thuộc device_id. ⇒ **decrypt OUTER mọi X-Argus của build này, offline, không phone.**

## Cách định vị (reproducible trong `mobile/unidbg` harness)
1. **SIGN_WLOG** (WriteHook): ghi mọi store 8B high-entropy từ code metasec trong lúc ký → khớp value với ciphertext ⇒ **PC `+0x159f2c` ghi 34/34 chunk** của ct.
2. **Hàm cipher**: setup `0x159d70` (gọi key-schedule `0x1591bc`, `w2=16` ⇒ AES-128) → CBC-loop **`0x159de4`**`(x0=ctx[roundkeys@0, iv@+0x1e8], x1=plaintext, x2=out, x3=len)`.
3. **SIGN_OUTER** (hook `0x159de4`): `rk0 = word-byteswap(aes_key)`; đọc `aes_key=8252970d…`, `aes_iv=4d207ea3…`, plaintext.
4. **Verify**: `AES_CBC_enc(PT, aes_key, aes_iv) == ct` ✅ và `dec(ct)==PT` ✅ (mode = **CBC chuẩn**, không CFB/OFB/CTR).

Chú ý điều tra: OUTER argus **KHÔNG** dùng AES nội bộ `0x1590bc` (đó là store/keva AES) và **KHÔNG** dùng boringssl (`libttcrypto` AES_*/EVP không fire); cipher ghi buffer **trực tiếp, né libc memcpy** (đúng pattern direct-store). Harness ở trạng thái "SDK not init" **vẫn** chạy OUTER thật.

## Tại sao note cũ tưởng "chưa có key"
- `decode_xargus` (community) đòi pkcs7 → reject mẫu modern (không pad) → nhầm "sai key".
- Test community SIGN_KEY `ac1adaae…` → bad-pkcs7 (đúng, key đã rotate) → dừng sớm.
- Thực tế chỉ cần: bỏ pkcs7 + lấy đúng SIGN_KEY = PSK material của build.

## Bảng AES trong `.so` (đã verify stock)
Te0@`0x198fe4`, Td0@`0x199fe4`, Td4@`0x19afe4` = byte-match AES chuẩn (note 30 ghi "0 AES tables" là SAI; ĐÍNH CHÍNH).

## Deliverables
- `huongB_devirt19/xargus_outer.py` — decoder OUTER offline (`decrypt_outer(b64)`), self-test PASS trên mẫu genuine.
- Hook env-gated thêm vào `/e/tiktok_signer/mobile/unidbg/.../Harness.java` (vô hại, off mặc định):
  `SIGN_KEYDUMP` (MD5 0x15b594 + SM3 0xa0748), `SIGN_AESDUMP` (0x1590bc), `SIGN_BSSLAES` (boringssl AES/EVP),
  `SIGN_CIPHERLOC` (memcpy locator), `SIGN_WLOG` (store-vs-ct matcher), `SIGN_OUTER` (0x159de4 key/iv/PT dump).
- Recipe ký offline: `MS_VENDOR=libs_trill/ MS_LIBS=libs_trill MS_SIGN_OFF=0x9ecc0 MS_DISP_OFF=0x11a1e0 MS_LICENSE_FILE=license_mus554.txt MS_REALINIT=1 MS_AID=1233 MSB_KV=1 MSB_INIT2=1 FIXTIME=<s> SIGN=1 SIGN_OUTER=1`.

## Tầng INNER — CRACKED (2026-08-24, verified end-to-end)
Từ plaintext OUTER (PT, header `ec..01..18` + body Simon) → **protobuf report** (magic 1077940818):
```
rb01 = x-argus_raw[:2]              # = header, cũng vào simon_key
rb23 = PT[-15:-13]                  # 2 byte đầu của tail 15B
rb   = rb01 || rb23
region  = PT[9 : -15]                                    # strip 9B header + 15B tail
simct   = reverse(region); xa=simct[:8]; simct[i>=8]^=xa[i%4]; simct=simct[8:]   # reverse-XOR (bỏ 8B)
report  = SIMON-128/256-decode(simct, key = SM3(SIGN_KEY + rb + SIGN_KEY)[:32])
report  = 08 d2 a4 80 82 04 …       # field1 = 1077940818 (argus magic), rồi aid "1233", device_id, version…
```
- Overhead framing = **9 (header) + 8 (xor-array) + 15 (tail) = 32B**; `report = len(PT) - 32`.
- SIMON = Simon128/256 (72 round), reuse `mobile/_websign/armxe/Mobile/cipher/SIMON.py` — dùng lại thuật toán community, chỉ khác **KHÔNG pkcs7** + framing 9/-15.
- **Verified**: harness ground-truth (rb=`0217d854` bắt từ SM3(sk‖rb‖sk)) decode ra protobuf ✅; **4/13 mẫu genuine device** → protobuf hợp lệ (aid 1233, device_id `7632162877655729682`, `v05.02.06/45.0.3`). Decoder: `huongB_devirt19/xargus_decode.py`.

### Còn pin: 9/13 mẫu genuine dùng framing/`rb` variant (điều tra cạn 2026-08-24)
- 9 mẫu AES-decrypt đúng (cùng SIGN_KEY, cùng header `ec..01..18`, **cùng version 45.0.3**) nhưng Simon ra rác với framing chuẩn.
- **Đã brute cạn, tất cả 0 hit cho nhóm này:** full `rb23` (65536, rb01=raw[:2]); `rb01'` (65536)+`rb23=PT[-15:-13]`; `rb`=2byte tổng; HDR 0-33 × TAIL 1-79 (rb23=tail-start); TAIL∈{15,31,47,63}×full rb23. Relaxed byte0==0x08 → 284 hit ngẫu nhiên, **0 cái có `d2a4`** (magic) ⇒ report của nhóm này KHÔNG ra `08 d2 a4` dưới framing chuẩn — dù `raw_getseed` **cùng size 498** lại decode được.
- ⇒ Nhóm này dùng **`rb`/framing khác bản chất** (không suy được bằng brute). KHÔNG phải bế tắc thuật toán (OUTER + chuỗi INNER đã proven; 4/13 + harness ra protobuf thật).
- **Cách đóng dứt điểm (2 đường):**
  1. **RE code framing** trong `.so`: AES-CBC ở `0x159de4` ← wrapper `0x10c358`/`0x10d1a0` (fn `0x10c358`) ← hàm ráp PT (header+reverseXOR+rb23) ở tầng cao hơn (OLLVM, nhiều tầng) → đọc quy tắc đặt `rb23`.
  2. **Bắt `SM3(sk‖rb‖sk)` live** cho 1 mẫu nhóm này (như harness) → biết `rb` thật → suy vị trí `rb23`.

### RE code framing (2026-08-24) — chạm tường VM-dispatch
- **Backtrace argus AES-CBC (harness):** `0x159de4 ← 0x10cf24 (AES-mode dispatcher 0x10c358) ← 0x9bc50 ← 0x95a9c ← 0x8e304 ← 0x8e2e8`. Hàm ráp PT = **`0x9bc50` (entry `0x9b394`)**.
- `0x10c358` = **AES-mode dispatcher generic** (gọi 0x159de4=CBC, 0x159618=block, 0x15a1dc/2b8/598/628 = CFB/OFB/CTR…). KHÔNG có framing argus. Được gọi **gián tiếp** (0 BL tĩnh, không trong .data.rel.ro).
- `0x9b394` (framing fn) = **VM-dispatched**: chỉ vài BL (stack-chk, `0x52924`); phần còn lại **BLR/indirect** → static RE bị chặn (cùng tường VM như slot16 `0x55950`).
- **Framing constants xác nhận (từ harness ground-truth):** `HDR=9`, `TAIL=15` (marker **`PT[-1]=0x0d=13=TAIL-2`** ở cả 13 mẫu), `rb01`=x-argus header (KHÔNG lưu trong PT), `rb23`=`PT[-15:-13]` (chỉ cho case "simple").
- **9-variant `rb` KHÔNG positional:** brute cạn — không phải `rb01=raw[:2]+rb23`-bất-kỳ-vị-trí-PT, không 4-byte-liền trong PT/raw, không `rb`=2byte, không rb01'. ⇒ `rb`/simon_key của nhóm này derive theo cách khác (nhiều khả năng = **code path non-degraded** mà harness "SDK not init" không tái tạo; hoặc rb sinh trong VM-framing).
- ⇒ **Đóng 9-variant cần: (a) devirt VM-framing `0x9b394` (multi-session, như slot16), HOẶC (b) live-capture `SM3(sk‖rb‖sk)` trên phone cho đúng report-type đó.** Ngoài tầm brute/static.

## 🎯 NGUYÊN NHÂN 9-variant — XÁC ĐỊNH (2026-08-24, không phải framing/VM)
Phân tích lại chính xác: **framing của 9 mẫu GIỐNG HỆT** 4 mẫu working (HDR=9, TAIL=15 qua marker `PT[-1]=0x0d`, cùng size pas_3=pas_4=562). Khác biệt DUY NHẤT = **key material của tầng Simon**.

**X-Argus modern dùng HAI PSK riêng:**
```
OUTER AES  : key/iv = md5(LICENSE_PSK halves)   LICENSE_PSK = c02f250f… (BUILD-CONST, ỔN ĐỊNH)
INNER Simon: key = SM3(SESSION_PSK + rb + SESSION_PSK)[:32]
             SESSION_PSK: bootstrap == c02f250f ; sau session/login refresh → ROTATE ≠ c02f250f
```

**Bằng chứng (device 7632, một session):** split TEMPORAL sạch —
- working pas_1/2/3 `_rticket`=1781808**230–280** (bootstrap) → Simon dùng c02f250f → decode OK.
- failing pas_4-12 `_rticket`=1781808**315–365** (sau gap 35s, quanh **fido2/begin_login**) → Simon dùng SESSION_PSK đã rotate → full brute `rb` với c02f250f = 0 hit.
- OUTER AES = c02f250f cho **cả 13** (all decrypt) ⇒ AES-PSK ổn định, chỉ Simon-PSK rotate.
- Loại: pskVersion (pas_2/3 = "0"+#18/#19 vẫn OK), version, endpoint, size.

**Cơ chế rotate (khớp slot16 §29/§37):** SESSION_PSK = f(license + keva triplet `sdi/ecneuq/semithc`). Session/login event → triplet update → PSK re-derive.

## ✅ Hướng 1 — LIVE CAPTURE SESSION_PSK (phone thật, 2026-08-24)
Phone `ce051605`, musically 45.5.4, `.so` md5 02f47578 (khớp crack), frida `msnkd:47119`.
- **Hook SM3 `0xa0748`, lọc block `X‖rb(4)‖X` (block[0:28]==block[36:64]) → X = SESSION_PSK.** Script: `huongB_devirt19/session_psk_capture.js`. Single minimal hook (né anti-frida, slot16 §33.5).
- **Bắt được LIVE: `SESSION_PSK = c02f250f…`** (= LICENSE_PSK, bootstrap).
- **203 argus signs / 190s (cold-start + bg/fg cycles + navigation) → TẤT CẢ c02f250f** (distinct=1, rb đổi 203 lần). ⇒ **SESSION_PSK ỔN ĐỊNH TRONG-SESSION** (khớp slot16 §33 "constant across session").
- ⇒ **Refine root cause:** split của 9 mẫu cũ (device 7632) = **ranh giới CROSS-SESSION** — capture cũ straddle một **login flow thật** (`token/beat scene=boot` → `store_region` → `fido2/begin_discoverable_user_login`). pas_1/2/3 = session-A (PSK=c02f250f), pas_4-12 = session-B sau login (PSK rotated). Rotation kích bởi **login/session-change**, KHÔNG bởi feed/lifecycle (203 signs chứng minh).
- ⇒ Tool PROVEN. Bắt PSK rotated cần: đưa app tới **màn login** (fido2 fire → provisioning session mới), cần logout/guest-state hoặc account.

## Decoder (cập nhật parametric)
`huongB_devirt19/xargus_decode.py` : `decode_xargus(b64, session_psk=SIGN_KEY)`.
- Bootstrap-window: default (c02f250f) → decode offline, không cần phone. Verified 4/4 + harness.
- Session rotated: truyền SESSION_PSK bắt live (session_psk_capture.js) → decode.
- **9 mẫu cũ KHÔNG decode được retroactively** (SESSION_PSK của session đó đã mất). Session mới thì decode được (capture PSK live).

## Còn lại
- Bắt giá trị SESSION_PSK **rotated** (≠c02f250f): cần trigger login-flow trên phone (fido2/passport), không phải feed.
- SIGN_KEY/framing đổi theo app version? (verify 45.5.4). Version khác → re-extract `SIGN_OUTER`.
