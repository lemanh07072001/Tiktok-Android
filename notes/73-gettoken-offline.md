# Note 73 — get_token: offline characterization (signer-grade + exchange decode)

> Task (user 2026-09-05): "tiếp tục giải get_token". Phạm vi OFFLINE — không gửi server
> (send/replay = human decision). Tường devreg-TRUST (note 24/25: ec7 velocity + fingerprint-forge,
> genesis bất khả kiến trúc) KHÔNG đập lại — note này chỉ giải mssdk exchange + năng lực ký offline.

## §1. Exchange get_token trên wire — DECODE LẦN ĐẦU (từ note-71 pcap gs2 + keylog2)

Request POST `https://mssdk22-normal-alisg.tiktokv.com/sdi/get_token?` query **274 ký tự, 16 param**
(`lc_id, platform, device_platform, sdk_ver, sdk_ver_code, app_ver, version_code, aid, sdkid,
subaid, iid, did, bd_did, client_type, region_type, mode`) — query **byte-identical trên cả 3 POST
mssdk** cùng connection (get_seed 131B, dyn/task 180B, get_token 724B). Header đáng chú ý:
`x-bd-kmsv: 0` (cả 3), `x-ss-stub`=MD5(body), **x-argus = 772 b64 trên cả 3** (north-star).

Body 724B = protobuf `{f1: varint 1077938244, f2: 2, f3: 2 (get_seed=4), f4: bytes[704] MÃ HÓA, f5: ts}`.

**Response (S2C sid8) — chưa từng được ghi chú trước đây:** `:status 200, content-length 76`,
body = `{f1: 1076102692, f2: 2, f5: 2, f6: bytes[64] MÃ HÓA}`. Tương tự dyn/task response
(S2C sid4, 44B): `{f1, f2:2, f5:4, f6: bytes[32]}`. get_seed response f6=176B (note 21, br-framed).

**Mọi blob đều bội số 16B** (704/64/32/176/112) ⇒ hợp AES/SM4 block cipher.

## §2. Signer ký được get_token — #19 law giữ nguyên, slot16 endpoint-ĐỘC LẬP

3 run A/B (store mặc định phone_sync, MSB_SM3CAP @0x9fdac):

| Run | URL | #19 | #13 | #14 | đuôi `00‖slot16[4:]`@~278 |
|---|---|---|---|---|---|
| feed (baseline §72.11) | api22 feed/offline/v2?pull_type… | f7874e8c… | d4aca5685605 | d057de8c… | **ABSENT** |
| get_token | mssdk /sdi/get_token?<Q274 nguyên văn> | 5944da5f… | d4aca5685605 | 571654ce… | **PRESENT** |
| get_seed | mssdk /ms/get_seed?<Q274 y hệt> | 5944da5f… (=get_token) | d4aca5685605 | 571654ce… | **PRESENT** |
| feed+mssdkQ | api22 feed path?<Q274> | 5944da5f… | d4aca5685605 | 571654ce… | **PRESENT** |

Kết luận:
1. **#19 = SM3(Q ‖ slot16 ‖ #20)** xác nhận cho URL-class mssdk; Q = query-string nguyên văn
   (274 ký tự, gồm cả `sdkid&subaid&bd_did` param rỗng không có `=`).
2. **slot16 = `46c0…b754` GIỐNG NHAU cho mọi URL** ⇒ với device này slot16
   endpoint-độc-lập (đơn giản hóa mô hình per-endpoint map — các giá trị khác nhau trong
   `endpoint_slot16_map.json` chắc chắn là các rotation/phiên capture khác nhau, không phải per-endpoint).
3. Query get_token **tĩnh 100%** (không ts/_rticket) ⇒ #19 deterministic offline hoàn toàn.
4. **Đuôi `00‖slot16[4:]` (12B device-key) sau field #36 — trigger = QUERY** (bộ param mssdk),
   không phụ thuộc path/host. .so emit sẵn trong signer (không cần thao tác gì thêm).
5. Signer emit đủ field, sign clean (exit-PC=0x9f078) cho URL-class mssdk.

## §3. Field linkages mới (từ store phone_sync, MSB_SECDUMP → cap.noindex/secdump/)

- **#32 = rtk2_ms** (50 hex chars → 25 bytes, byte-exact `unhex(rtk2_ms)`) — giải thích
  "#32 absent" của unidbg degraded cũ (note 32): thiếu rtk2_ms trong store.
- **rdk2_ms = device_id** (chuỗi số thuần, = `did` trong query get_token).
- phone_sync (sync ~03-04/09) dyn_seed == capture phone 04/09 19:04 (`dyn_last_update_time`
  1788523340) — **trước** pcap 05/09 10:14 ⇒ dyn_seed đã rotate giữa 2 mốc; KHÔNG có cặp
  known-plaintext cùng session cho f6 (xác nhận bằng mtime artifacts, reader 2026-09-05).
- Key-candidates device-stable hợp lệ cho blob 05/09: rtk2_ms, kiid, rdk2_ms (+MD5/derivatives).

## §4. W2 — battery decrypt blob f4/f6 (KẾT QUẢ: 0 hit — đã cạn đường đen)

Blobs từ `cap.noindex/gettoken_wire/blobs.json` (_mssdk_blobs.py). 3 vòng:

| Vòng | Keys | Ciphers/modes | Kết quả |
|---|---|---|---|
| R1 | 27 ứng viên device-stable (SIGN_KEY+halves, rtk2_ms/kiid/rdk2_ms+MD5/hex, MD5("1233-0-1-sdi"/ecneuq/semithc), MD5(SHA1(sdi_v2)), zeros) | AES-ECB/CBC0/SM4-ECB, oracle PB lỏng | "hit" toàn nhiễu (oracle tag hợp lệ ~15%/thử) |
| R1' | như R1 | oracle CHẶT (protobuf-walk đệ quy 100% consumed / zlib / printable) | **0/6** (1 hit đơn lẻ 32B = nhiễu) |
| R2 | slot16 làm key + SM3/MD5/SHA derivations, 2 req-key cũ note-54, devIV | + CTR/OFB/CFB | **0/6** |
| R3 | RC4 họ store: MD5(SHA1(tên file .msp/.mss/.msf3 thật từ backup phone)), sdi_v2, 8fd6b14a… | RC4 drop 0/256/768 | **0/6** |

Phân tích cấu trúc: không block-16 lặp (loại ECB cùng-key lộ pattern), không prefix chung
(không header cleartext), XOR-pair mọi cặp blob = nonzero ~100% (không keystream-reuse).
⇒ key không phải hàm phẳng của bất kỳ device-stable nào ⇒ chuyển đường **capture sống**.

## §5. ★★★ TƯỜNG KHÓA VỢ — LIVE CRYPT CAPTURE (3 runs, 2026-09-05 chiều)

Tool mới: `huongB_devirt19/_mswire_crypt.js` + `_cap_mswire.py` — passive (spawn + usage
bình thường, KHÔNG xóa store, KHÔNG ép trigger; app cold-start tự fire cả 3 exchange mssdk).
Hooks (libmetasec_ov.so 2032384B, ABI từ notes 54/56): KEYSCHED `0x1591bc` (x1=userKey),
CBC_ENC `0x159de4` / CBC_DEC `0x159f58` (x0=ctx,x1=in,x2=out,w3=len; ctx-key=wswap4(ctx[0:16]),
IV@ctx+0x1e8), INIT `0x159d60/0x15a1dc/0x15a598`, RC4 `0x10bbd0` mọi caller + out,
SM3 `0x9fdac`, block `0x159618/0x159d1c`. Full-buffer dump theo size. Output git-ignored
`cap.noindex/gettoken_crypt/crypt_*.jsonl` (3 runs: 151113/151444/151946).

### §5.1 CIPHER NGOÀI CỦA WIRE f4/f6 — SOLVED + VERIFIED

**f4 (request) và f6 (response) = AES-128-CBC, PKCS7**:
- key `b8d72ddec05142948bbf2dc81d63759c` — chính là "ứng viên store-key chưa verify" note-54!
- IV `d6c3969582f9ac5313d39c180b54a2bc` (lưu trong ctx+0x1e8, hằng trong mọi call)
- Verify 2 chiều: (a) mọi DEC sống 176/96/64/32B đều key/IV này; (b) **6/6 blob pcap sáng
  cùng ngày** (khác session!) decrypt ra **PKCS7 hợp lệ** (pad 0x0b×8, 03×3…) ⇒ key/IV
  ổn định theo ngày, khả năng cao là hằng app (xem §5.3).
- Caller: DEC từ lr `.so+1105048`, ENC từ lr `.so+1102244` (mọi wire-size 112/160/704/176/32/64).

### §5.2 CIPHER BODY x-argus — SOLVED, 62/62 BIT-EXACT

Mỗi api-request: `ENC len ∈ {480,496,512,560,576,592,608}` key `8252970d959b06db102e17d85c0ec1af`
IV `4d207ea37a419f7d622f81c6a2f53594` — **recompute ct từ pt khớp 62/62 mẫu bit-exact.**
- Số học khớp north-star: pt 576B → ct 576B → b64 = 768 ký tự + 4 prefix = **772 = len x-argus**.
- Định dạng pt: `[0xEC const][3B nonce][~568B body VM-encoded]` — const-map 62 mẫu: chỉ ~8 vị trí
  hằng ≥90%, toàn body biến thiên theo request ⇒ **lớp TRONG vẫn là VM** (cùng tường với
  EMISSION wall note-58/72). Nhưng giờ đã có **62 mẫu pt thật** làm known-plaintext corpus.
- Key thứ 3 `b114249b7bed9d2691d70c60d69f9c4f` (KS, lr `.so+1104816`) — vai trò TBD
  (nghi x-gorgon/ladon path). Key AES-256 ASCII-hex `“236509d6fc8fa5378276e4d48144da29”`
  (kb=32, KS 1 lần) — nghi container .mss; không khớp hash của material đã biết.

### §5.3 BA KEY ĐỀU LÀ APP-CONSTANT (chết giả thuyết "key sinh trong VM" cho 2 đường này)

Cả 3 key (`8252970d`, `b8d72dde`, `b114249b`) bắt được **trên phone ce0516 hôm nay** đều
**trùng hệt** giá trị hook trên **emulator 31/08** (note-54 §3: req#1 8252970d + IV 4d207ea3
nguyên văn; b8d72dde = wswap của schedule de2dd7b8). Key/IV không phụ thuộc device/session
⇒ deterministic, đưa vào signer/tooling được trực tiếp.

### §5.4 LUỒNG mssdk SỐNG (chuỗi sự kiện quanh DEC-64 = get_token response)

`ENC 576 (report api) → SM3(274-Q mssdk) [#19/#14 law sống] → SM3(16B)=SM3(slot16) ×34
[#13] → DEC 64 (get_token resp) → SM3(66-query mới)` — query 274 ký tự nguyên văn
`lc_id=2142840551&platform=android&device_platfor…` == Q của pcap. DEC-64 fire **2 lần**
trong run-3. RC4 caller khác-store lr `.so+1097964` (0x10b6fc): input 125/126/127/281B
mỗi request (nội bộ sign) — chưa dựng.

## §6. STORE SEMANTICS qua RC4STORE (plaintext `[4B LE len][zlib(JSON)]`)

- **Seed record** (370→494B JSON): `kiid, dyn_seed(132b64), dyn_deviceid, fltk, rep_vd:true,
  rdk2_ms(=device_id), rtk2_ms(50hex, **đổi giá trị giữa 2 lần ghi** — có timestamp nhúng),
  schedule_report_interval:18, bootsoft, rsk2_ms:2 (int!), dyn_version:1, dyn_last_update_time
  1788596424 (= trong cửa sổ capture — seed vừa được refresh), server_tsp_diff 421→397`.
- **Counter store** (124/125B): `1233-0-1-semithc:"208", 1233-0-1-ecneuq:"207",
  3019-0-1-26d9e709d5ef8ec4366d941ac5b97ee7:"747188776→217561513"` — các keyname họ
  "1233-0-1-*" là **COUNTER, không phải key** (battery R1 MD5(keyname) không bao giờ hit được).

## §7. Còn lại (tường duy nhất) + next steps

1. **Lớp TRONG (VM codec)** — rào cản cuối cho BOTH: nội dung f4 attestation (704/160/112B
   pt opaque), f6 response (64B pt opaque), và x-argus body (0xEC…). Giờ đã có corpus
   known-plaintext dồi dào: 62+ report pt + f4/f6 pt sống + store JSON ngữ nghĩa tương ứng.
2. Next: (a) attack codec VM với corpus (so.pt có [0xEC][nonce][body] — thử XOR keystream
   SM3/RC4(key,nonce), so với format signer-emit); (b) static-RE caller lr +1102244
   (report builder) / +1105048 (response handler) — 2 hàm duy nhất cần devirt;
   (c) KS ASCII-hex-256 "236509d6…" — xác định vai trò (.mss?).
3. Vệ sinh: pt f4/f6 + report pt đều nằm `cap.noindex/gettoken_crypt/` (git-ignored);
   KHÔNG ghi giá trị secret (dyn_seed/rtk2/kiid đầy đủ) vào notes — đã redact §6.

## §8. FIVE SUB-GAPS SOLVED (2026-09-05, offline — user "giải cho tôi")

Tất cả offline, không gửi server. Tool tái lập: `huongB_devirt19/_qpack_xargus.py`
(task-1), `sm3_hash19.py` (task-5), phân tích jsonl (task-2/3/4).

### §8.1 ★ Task-1 — VERIFY CHUỖI 772 END-TO-END (wire → plaintext) = PASS
QPACK-decode header thật từ pcap (`ground-truth/getseed_wire/decoded/mssdk22-normal-alisg…`).
Cơ chế: **x-argus (772 ký tự) KHÔNG nằm literal trong request** — nó được **insert vào QPACK
dynamic-table qua encoder stream (sid10, 5504B)** rồi request chỉ **tham chiếu bằng index**
(vì thế HEADERS block chỉ 57–65B). Feed encoder stream vào pylsqpack Decoder(65536,100) →
resolve index → đọc được giá trị x-argus thật. **Cả 3 POST mssdk cùng connection:**

| stream | endpoint | body | x-argus | hdr2 |
|---|---|---|---|---|
| sid0 | /ms/get_seed | 131B | **772 ký tự** | edbc |
| sid4 | /ms/dyn/task | 180B | **772 ký tự** | 4b51 |
| sid8 | /sdi/get_token | 724B | **772 ký tự** | 20b3 |

Cấu trúc CHÍNH XÁC (sửa mô hình "4-char prefix + 768" của §5.2): 772 ký tự b64 (kết thúc
đúng **1 ký tự `=`**) → decode = **578B = `[2B header][576B ct]`**. AES-128-CBC(key
`8252970d…`, IV `4d207ea3…`) trên 576B ct → **pt[0] = 0xEC trên cả 3** (đúng const-marker
§5.2), format `[0xEC][3B nonce][572B VM-body]`. Đuôi pt const chung `…1f 7d/7e … 0d`.
⇒ North-star 772 chứng minh **từ byte wire thật → plaintext có cấu trúc**, không còn là số học.
Header khác đọc được: x-gorgon (26B), x-ladon (48B b64), x-khronos (ts), x-ss-stub=MD5(body),
x-bd-kmsv=0, x-tt-store-region=vn. `x-argus[:2]` header 2B khác nhau mỗi request (nonce-linked).

### §8.2 Task-2 — VAI TRÒ 4 KEY (KS events, redacted)
4 key được keyschedule; xác định vai trò qua INIT(stream-init) + nhóm ENC/DEC theo ctx-key:

| key (prefix) | kb | lr KS | INIT? | CBC-ENC/DEC? | VAI TRÒ |
|---|---|---|---|---|---|
| `8252970d…` | 16 | +1416592 | ✓ w2 iv=4d207ea3 @+1102048 | ENC {…576×58,592×32…} @+1102244 | **x-argus body** (xác nhận lại) |
| `b8d72dde…` | 16 | +1416592 | ✓ w2 iv=d6c39695 @+1102048 | ENC{160,112,704}+DEC{176,96,64,32} @+1102244/+1105048 | **wire f4/f6** (xác nhận lại) |
| `b114249b…` | 16 | +1104816 | ✗ | ✗ (không CBC, không INIT) | **key thứ 3 app-const, đường x-gorgon/x-ladon** (đúng nghi vấn) — schedule tại builder gorgon/ladon +1104816, KHÔNG chạm 2 body-cipher |
| `32333635…`="2365…"(ASCII) | **32** | +1102020 | ✗ | ✗ | **AES-256 one-shot lúc init**, key = **chuỗi ASCII-hex** "236509d6…" (dùng 32 ký tự ASCII làm 32-byte key — dấu hiệu whitebox/embedded); KHÔNG per-request, KHÔNG wire ⇒ **giải container tĩnh (.mss-class) 1 lần** |

Chốt: chỉ **8252970d & b8d72dde** là 2 body-cipher AES-128-CBC per-request. `b114249b` và
`236509d6-ASCII` scheduled nhưng KHÔNG qua CBC/INIT ⇒ feed primitive khác (gorgon/ladon +
container init).

### §8.3 Task-3 — RC4 NON-STORE caller +1097964 (0x10b6fc) DỰNG XONG (RC4 tất định → recompute offline)
insz-hist: `{124:4, 125:14, 281:119, 372:1, 630:1}`. **Hai công dụng:**
- **124/125B in → RC4 → `[4B LE len=162][zlib]` → inflate 162–163B JSON** (envelope Y HỆT store
  record §6 nhưng là blob **per-request in-memory** — đọc state/config mỗi request; key 32B).
- **281B in (×119, áp đảo), key 20B (cỡ SHA1) → 281B nhị phân entropy~6.0** = **biến đổi ký
  per-request** (không zlib). Đây là "nội bộ sign mỗi request" của §5.4 — RC4 keystream trên
  buffer canonical cố định 281B với key SHA1-class đổi mỗi request. Output tái dựng offline OK.
- (phụ) caller +638904: 12B in → protobuf nhỏ ×3 (không liên quan wire).

### §8.4 Task-4 — ĐIỀU KIỆN FIRE get_token
get_token response = **DEC len 64** (giải f6:bytes[64] của response 76B §1). Đếm 3 run:
`run1=1×, run2=1×, run3=2×`. Mỗi cold-start có 4 DEC mssdk: **176(get_seed) / 96(?4th) / 64(get_token) / 32(dyn/task)**, mỗi cái 1× — RIÊNG get_token 1–2×.
⇒ **get_token KHÔNG do .dy/tasks lập lịch** (.dy/tasks chỉ /ri/report) — nó là **call bootstrap
nội bộ của mssdk SDK lúc cold-start** (chuỗi get_seed→dyn/task→get_token khi SDK cần token/seed).
Context 2 lần fire (run3): lần-1 `ENC576 RC4.281 SM3.49 SM3.16 → DEC64` (dựng x-argus tươi +
#14/#13 law rồi lấy token); lần-2 `RC4.124 RC4.281 → DEC64` (chỉ đọc state + sign, **không**
build attestation mới) ⇒ **fire thứ 2 = refresh token từ cached-state**, không tất định
(chỉ xảy ra run3). Luật: **≥1 lần/cold-start (bootstrap), thỉnh thoảng +1 refresh**.

### §8.5 Task-5 — pskVersion (#20) của genuine capture = **"0"** (ĐÃ CHỨNG MINH DUY NHẤT)
Không cần đọc body VM-encoded: #19 = SM3(Q ‖ slot16 ‖ #20) là **oracle known-plaintext**.
Brute #20 ∈ {`0`,`none`,`1`,`2`,``,`00`,`0\x00`,`device`,`psk`} trên **11 tuple ground-truth
slot16≠0** (`ground-truth/hash19_nonzero_tuples.json`) → **CHỈ `b"0"` khớp 11/11**, mọi ứng
viên khác 0/11. Cross-confirm: `_SIGNER_D19`, `_EXAMPLE_D19` (sm3_hash19.py) và note-59
fresh-state tt.Dump (hiện #20="0" trực tiếp). ⇒ genuine #20 = ASCII '0' (0x30), tất định.

### §8.6 TƯỜNG DUY NHẤT CÒN LẠI (không đổi)
Lớp TRONG VM-codec: 576B pt x-argus `[0xEC][nonce][VM-body]`, pt f4 attestation (704/160/112),
pt f6 response (64/96) — đều opaque (protobuf-walk byte-0 = rỗng). Đã có corpus known-plaintext
dồi dào. 5 sub-gap wire/key/fire/pskver = ĐÓNG; chỉ còn devirt 2 caller (+1102244 builder /
+1105048 handler) — quyết định human (giá trị thấp, note-65 + cyber-flag).

## §9. KẾ HOẠCH tấn công TƯỜNG CÒN LẠI (VM-codec) — next session

Tài sản mới (task-1): **3 body wire cùng session, Q byte-identical** (get_seed/dyn_task/get_token)
→ bộ đối chứng có kiểm soát. Thí nghiệm quyết định (chưa chạy — bị ngắt):

1. **XOR-pair 3 body 572B** (sau khi bỏ `[0xEC][3B nonce]`): nếu có **zero-run dài** ở vùng
   field tĩnh (Q-derived: #14=SM3(Q)[:6], #20="0", app-ver…) ⇒ codec **keystream-HẰNG** →
   crack bằng known-plaintext ngay. Nếu **all-nonzero** ⇒ keystream **theo-nonce** → cần generator.
2. **Localize known values**: search body cho #14=SM3(Q)[:6], #13=SM3(slot16)[:6],
   #19=SM3(Q‖slot16‖"0") (32B) — thử biến đổi: reversed / nibble-swap / XOR(nonce lặp) /
   XOR(SM3(nonce)) / XOR(AES(key,nonce||ctr)). Nếu tìm thấy ⇒ định vị codec.
3. **Key candidates MỚI cho inner-codec** (chưa thử ở round-1): **`b114249b`** (key thứ 3
   app-const, KS@+1104816, KHÔNG dùng CBC/INIT — ứng viên mạnh cho stream/CTR inner) và
   **BLK single-block** @+1417004 (x0=`0d975282`=wswap của 8252970d → nghi AES-CTR keystream
   block: `AES_enc(key, nonce||counter)`). Thử cả 2 làm keystream over nonce.
4. Nếu (1-3) miss ⇒ devirt tĩnh 2 caller `+1102244` (report builder) / `+1105048` (resp handler)
   — nhưng note-39 VM-divergence + note-65 giá trị-thấp ⇒ cân nhắc human trước khi đốt session.

Không gửi server (giữ nguyên human-gate). Corpus: cap.noindex/gettoken_crypt/ (git-ignored).
