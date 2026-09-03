# 37 — X-Argus ENCODER (report → X-Argus) — SOLVED + ROUND-TRIP VERIFIED (2026-08-24)

> Nối [[36-xargus-outer-key-CRACKED]] (OUTER+INNER decode), [[30-xargus-inner-report-decoded]], [[33-hash19-pskcalhash-SOLVED]].
> **Mục tiêu**: đảo ngược decoder → ký X-Argus offline. **ĐÃ GIẢI toàn bộ tầng ENVELOPE (crypto + framing).**
> Deliverable: `huongB_devirt19/xargus_encode.py` — inverse bit-exact của `xargus_decode.py`.

## Kết quả (bằng chứng cứng — round-trip)
Decode 1 mẫu genuine → lấy `(report, rb01, tail, xa, header)` → `encode_xargus(...)` → **b64 TRÙNG BIT-EXACT** mẫu gốc.
- `_GENUINE` (embedded): **MATCH**.
- 12 mẫu capture thật `mobile/frida/out/passport/pas_*_req.txt`:
  - **pas_1/2/3 (bootstrap-window): round-trip MATCH 3/3** (report 432/496/528B).
  - **pas_4-12: magic MISS 9/9** — đúng là nhóm SESSION_PSK rotated (khớp §36; không decode được nên không round-trip được, KHÔNG phải lỗi encoder).
- ⇒ Encoder đảo ngược decoder **chính xác tuyệt đối** trên mọi mẫu decodable.

## Chuỗi mã hóa (inverse của xargus_decode.py)
```
report (protobuf, 16-aligned)
  -> simct  = Simon128/256-ENCODE(report, key=SM3(SESSION_PSK + rb + SESSION_PSK)[:32])
  -> region = reverse( xa[8] || [ simct[j] ^ xa[(j+8)%4] for j ] )     # inverse reverse-XOR
  -> PT     = header[9] || region || tail[15]                          # rb23=tail[0:2], PT[-1]=0x0d
  -> ct     = AES-128-CBC-enc(PT, aes_key=md5(SIGN_KEY[:16]), aes_iv=md5(SIGN_KEY[16:]))
  -> X-Argus = base64( rb01[2] || ct )
     SIGN_KEY = c02f250f… (build-const);  rb = rb01 || rb23
```
- **Simon forward** = `_simon_encode`: inverse Feistel của `_simon_decode`. Vòng i=0..71: `a,b = b, (a ^ f(b) ^ key[i])` với `f(x)=(rol(x,1)&rol(x,8))^rol(x,2)`. Verified bằng round-trip.
- **AES-CBC enc** dùng chính key/iv build-const (đã proven §36).

## PHÁT HIỆN: `rb` (rb01+rb23) và `xa` = **NONCE TỰ DO** (proven) — KHÔNG cần giải
Test (`xargus_encode` re-encode genuine report với nonce tùy ý → `decode_xargus` → magic + report):
```
rb01 ∈ {0000, ffff, 1234}      → decode magic OK, report MATCH  (3/3)
rb23 ∈ {0000, abcd}            → decode magic OK, report MATCH  (2/2)
xa   ∈ {0, deadbeef*2, 0011..} → decode magic OK, report MATCH  (3/3)
fresh rb01=7788 rb23=5566 xa=cafebabe*2 → magic=1077940818, report MATCH
```
⇒ **envelope chấp nhận rb/xa BẤT KỲ**: `rb` chỉ nuôi Simon-key (SM3(psk‖rb‖psk)); decode tự recompute cùng key → cùng report. `xa` chỉ là mask; decode tự recover `xa` từ region. ⇒ signer **tự chọn** rb & xa.
- (Caveat: đây là "envelope-valid" — server CÓ THỂ cross-check rb/xa theo rule sinh của app; chưa test live. Nhưng từ góc DECODER, hai giá trị này tự do hoàn toàn.)

### Quan sát về `xa` thật (khi RE rule sinh của app, nếu server cross-check)
`xa = reverse(region[-8:])`, nằm trong plaintext. Mẫu thật luôn `P||P` (4 byte lặp 2):
```
_GENUINE : 88f7fcff  | pas_1: c397ffff | pas_2: a0effeff | pas_3: 0837fbff
```
`~P` = 26684 / 69727 / 313079 / 198775 (số dương nhỏ). Giả thuyết: field 32-bit (len/counter) ghi 2 lần. Chỉ cần nếu server validate; envelope thì không.

## Trạng thái tổng — X-Argus offline sign
| Tầng | Trạng thái |
|------|-----------|
| OUTER AES-CBC (encrypt) | ✅ PROVEN (build-const key) |
| INNER Simon (encrypt) | ✅ PROVEN (forward Feistel, round-trip) |
| reverse-XOR framing (inverse) | ✅ PROVEN |
| Envelope assembly (report→b64) | ✅ PROVEN bit-exact 3/3 + genuine |
| `report` protobuf construction | ⏳ cần build (device_id/aid/version/ts + #18/#19; #19 SOLVED §33/memory) — **DUY NHẤT còn lại** |
| `rb01`/`rb23` (nonce) | ✅ PROVEN nonce tự do (envelope) — signer tự chọn |
| `xa` (P) | ✅ PROVEN nonce tự do (envelope) — signer tự chọn |
| SESSION_PSK | ✅ bootstrap=c02f250f offline; rotated cần live-capture (§36) |

## Validate #19 trên report genuine đã decode (2026-08-24)
Decode `pas_2`/`pas_3` (bootstrap, pskVersion="0") → lấy field #18/#19 thật, so với `sm3_hash19.compute_hash19`:
```
pas_2: 39/39 order-keys present. real#19=2fb9093a… calc(slot16=0)=2cb02223… → MISMATCH
pas_3: 39/39 order-keys present. real#19=f5f81658… calc(slot16=0)=6e05adf7… → MISMATCH
#18 (pas_2==pas_3) = 61c6c65ca6b4f03629db05466aff2645  (device-const của device 7632; ≠ #18 của SM-G930F)
```
- **Query đúng 100%** (39/39 key đúng thứ tự) → mismatch DUY NHẤT vì **slot16 ≠ 0** cho 2 sign này.
- Khớp doc: ~40% sign có `slot16=0` (ký offline được NGAY), còn lại slot16 per-request (đúng mục tiêu Track A/B VM).
- `sm3_hash19.py` self-test PASS (SM3 KAT + build_query + 1 live capture slot16=0). ⇒ **formula #19 đúng; biến số còn lại = slot16.**
- Tool: `_validate_hash19.py`.

## Còn lại để ký FROM-SCRATCH
1. **slot16** (16B per-request): =0 cho ~40% sign → ký offline được ngay; ≠0 cho 60% → cần Track A/B (bytecode VM) hoặc capture. **Đây là nút thắt còn lại**, trùng mục tiêu slot16 gốc.
2. **Dựng report protobuf đầy đủ**: template từ 1 genuine "0"-report + thay #18(device-const)/#19(computed)/device-state. Fields ổn định (memory xargus-offline-state §clean-diff): {1,2,4,5,6,7,8,9,18,20,21,23,28,30,32,33}.
3. rb & xa: nonce tự do (proven) — signer tự chọn.
4. Ghép → `encode_xargus(report, rb01, tail, xa)` → verify bằng `decode_xargus` (magic + #19 khớp).

**Kết luận turn này:** envelope (AES+Simon+framing) + rb/xa + formula #19 = XONG & proven. Từ-scratch signer giờ **chỉ chặn bởi slot16** (≠0 case) — đúng bài toán Track A/B đang làm; envelope không còn là rào cản.

## Verify cách chạy
```
cd huongB_devirt19 && python xargus_encode.py          # round-trip self-test (_GENUINE) → PASS
# multi-sample: extract x-argus từ pas_*_req.txt, decode→encode, assert bit-exact (3/3 bootstrap)
```
