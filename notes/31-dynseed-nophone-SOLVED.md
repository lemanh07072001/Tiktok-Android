# 31 — dyn_seed (report #24) = LẤY ĐƯỢC 100% NO-PHONE (verified); tác dụng-trust CHƯA test (2026-08-18)

> Mục tiêu: sinh field #24 (dyn_seed) của X-Argus report **không đụng phone lần nào**.
> Kết quả: **ĐẠT ở mức get_seed** (verified 3 góc: f4 112B cấu trúc genuine, response = dyn_seed 176B hợp lệ,
> re-POST độc lập từ Node did-mới → 200+seed). **CAVEAT:** get_seed LENIENT (bogus/forge f4-unidbg đều 200)
> ⇒ 200+seed **KHÔNG** chứng minh seed mang trust. Nhúng dyn_seed làm x-argus 280→368 nhưng **chưa test**
> nó có làm auth-endpoint tin hơn thin không (cổng auth = device-trust/velocity, note 24 W6/26/29).
> Lật giả định cũ `REVERSE_DYN_SEED.md` ("server-only, device-bound, cannot generate offline") + note 25 ("f4 device-bound").
> Nối [[30-xargus-inner-report-decoded]] (#24 = dyn_seed), [[21-mssdk-getseed-attestation]], note 23 G7.

## Chuỗi bằng chứng (tất cả từ PC, KHÔNG phone)

### 1. #24 = dyn_seed, đến từ get_seed API (network, không phần cứng)
- Report #24 (98B, prefix `3031`) = dyn_seed dạng keva. get_seed response `#6 = dyn_seed 176B`.
- Endpoint `mssdk*/ms/get_seed` **PC gọi được** (direct HTTP 200).

### 2. Anti-replay ≈ KHÔNG — replay request 28 NGÀY tuổi → 200 + dyn_seed TƯƠI
- `getseed_replay.json` (khronos 2026-07-21) replay 2026-08-18 → **HTTP 200, seed mới** (`905e0e84…` ≠ gốc).

### 3. get_seed validate ĐÚNG 1 thứ = f4 (112B); did/iid KHÔNG validate
Test mutate (giữ x-argus cũ), body 131B = `08 <f1> 10 02 18 04 22 70 <f4 112B> <f5>`:
| mutate | kết quả |
|---|---|
| real f4 (base) | 200 + seed 176B ✅ |
| **f4 = RANDOM** | 200 nhưng **12B, KHÔNG seed** ❌ (f4 bị validate) |
| **did = FORGE** (giữ real f4) | 200 + seed 176B ✅ (did KHÔNG validate) |
| body all random | 12B ❌ |
⇒ 1 f4 hợp lệ **tái dùng** với mọi did giả, sống ≥28 ngày. Tường #24 = **chỉ f4**.

### 4. 🎯 CHỐT: unidbg dựng f4 hợp lệ PURE-FORGE → server nhận
Chạy signer offline (`mobile/sign.mjs` → Harness unidbg) với collect-thread, **device forge random, KHÔNG devstate phone**:
```
cd mobile/unidbg
SIGN=1 FIXTIME=$(date +%s) \
  MSB_FULLINIT=1 MSB_THREADS=1 MSB_THREADS_SECS=12 MSB_NET=1 MSB_KV=1 \
  DID=<19-digit-random> IID=<19-digit-random> \
  java -Djava.library.path=native -cp "target/classes;$(cat cp.txt)" tt.Harness
```
Log (reproducible 3/3, DID khác nhau):
```
[*] MSB_FULLINIT done (did=7591892441932450481 iid=…)
JNIEnv->NewStringUTF("https://mssdk-sg…/ms/get_seed?…did=7591892441932450481…")
[*] MSB_NET 0x30001 GET_SEED POST body=131
[*] MSB_NET resp code=200 len=189      ← SEED TRẢ VỀ (khác f4-random=12B)
```
- **f4 unidbg dựng cho device chưa-từng-tồn-tại → server 200 + dyn_seed.** Metasec build f4 từ **SDK-init state** (unidbg init được bằng MSB_FULLINIT+MSB_KV, state RAM tự-nhất-quán, KHÓA unidbg — KHÔNG cần khoá/keva device thật).
- **X-Argus enrich:** baseline (no get_seed) = **280** → pure-forge + get_seed = **368** (+88 = dyn_seed nhúng). (Không dùng `MSB_DEVSTATE_DIR` — khác note 23 G7 vốn feed state phone.)

## KẾT LUẬN
- **dyn_seed (#24) sinh 100% no-phone = ĐẠT.** Pipeline: unidbg(FULLINIT+THREADS+NET+KV, forge DID/IID) → collect-thread dựng f4 → get_seed POST → dyn_seed → nhúng x-argus.
- **f4 KHÔNG device-hardware-bound** — là crypto blob metasec tính từ SDK-state; unidbg (sạch tuyệt đối) init được → dựng f4 hợp lệ. (Random f4 = reject; unidbg-f4 = accept ⇒ f4 có cấu trúc thật, reproduce offline được.)
- Đính chính `REVERSE_DYN_SEED.md` câu hỏi "offline hay server-only?": **fetch từ server BẮT BUỘC (network), nhưng request-build 100% offline pure-forge** — không cần phone.

## Còn lại (ngoài #24)
- #24 chỉ +88 byte (280→368). Genuine = 792. Gap còn lại = các device-state field khác của report (note 30):
  #16 device_token, #18 uuid16, #19 req_hash, #32 blob24… — mảnh tiếp theo tấn công.
- CHƯA test: x-argus-có-dyn_seed pure-forge này qua auth-endpoint có tốt hơn thin không (velocity/trust là biến riêng — note 24/25).

## Tool/artifact
- Repro: lệnh trên (`e:/tiktok_signer/mobile/unidbg`, Harness env `MSB_NET`).
- get_seed leniency test: mutate f4/did giữ x-argus (node fetch, ground-truth `getseed_replay.json`).
- Signer: `mobile/sign.mjs` `signOffline(url,block,khronos,{MSB_FULLINIT,MSB_THREADS,MSB_NET,MSB_KV,DID,IID})`.
