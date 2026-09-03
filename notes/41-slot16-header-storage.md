# Note 41 — slot16 storage = report-header k-v; producer behind obfuscation wall

Session 2026-08-25 (sau khi login gỡ chặn nonzero slot16). Track: Stalker/trace producer.

## Gỡ chặn (nền tảng cho mọi thứ dưới)
- Login TikTok (user7740317271020) → device "trusted" → **nonzero slot16 producer FIRE lại** ở cold-start.
  Trước đó fresh-device sau factory-reset = 0 nonzero (producer im).
- **Harness tái lập nonzero theo ý muốn**: wipe state SDK (bounded, an toàn) + spawn cold-start:
  * `adb shell su -c 'find /data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov -maxdepth 1 -type f -name ".ms*" -delete'`
  * `python _run_catch_spawn.py 110`  → bắt 5 nonzero/5s. Determinism: wipe → pool tái sinh cùng giá trị.

## slot16 lưu ở đâu (ĐỊNH VỊ CHÍNH XÁC)
- slot16 KHÔNG persist trong file .msp (search giá trị = 0 hit) → **derive runtime từ PSK-state**.
- Live: slot16 nằm trong **report-header k-v structure** (anon rw-, region base ~0x7ccc86a000, entries rải
  0x7ccc855xxx..0x7ccc8dxxxx). Layout mỗi entry:
  ```
  02 01 02 00 00 00 | KK KK | 00 00 00 00 00 00 00 00 | <slot16 16B> | <ascii keyname>
     tag cố định       keyid2B        8 byte zero          value        "K-VERSION"/"HOST"/"-TNC"
  ```
- **Cặp keyid→slot16 (ground truth, device hiện tại)**:
  * d243 → b8591fcb8d86ff40ed3989462a588bf1
  * 8fe9 → 46c03b52742b3f2615a3abdf1636b754
  * 9da7 → 0ea0d7182026ab52aefc78d73cded419
- Pool device-stable: cb12155b (3 spawn), b8591fcb (2 spawn) lặp lại. Cùng query → cùng slot16
  (b8591fcb ↔ "device_platform=android&os=android&ssmix").

## Đường đi của slot16 (flow)
- Internal memcpy **0x172a50**(dst=x0,src=x1,len=x2), gọi từ SM3-caller area (0xa0234), copy
  header(0x7ccc8xxxxx) → query buffer (0x79axxxxxxx). ĐÂY là lý do hook libc-memcpy trượt (dùng hàm nội bộ).
- Chuỗi tới SM3 (return-addr, backtrace an toàn): SM3(0xa0748) ← 0xa02ac ← 0xa05b8 ← 0x9fe98 ← 0xa101c
  ← **0x55950 (VM interp)** ← 0x13a7b8 ← 0xa103c ← 0x1864f0 ← 0x1d9680 ← **0x9b614 (closure invoker)**
  ← **0x9fd74 (report-assembly)**. VM chạy như ancestor.

## Producer = header-builder, sau bức tường obfuscation
- Producer GHI slot16 THẲNG vào header k-v ở SDK-init (một lần), KHÔNG qua 0x172a50
  (memcpy-trace dst-in-header, filter tag/keyname = 0 hit) → ghi bằng str trực tiếp trong code obfuscated/VM.
- **.so on-disk bị PACK/mã hóa**: bytes @0xa0140 = 0x004778b0 không decode được offline (capstone n=0);
  chỉ giải mã ở runtime. (Giải thích luôn unicorn walls suốt project.)
- Disasm LIVE hàm gọi SM3 = **control-flow flattening**: `br x9/x8` computed qua `madd/csel/and/eor`
  (opaque predicate), fake-return `adr;mov x30;ret`, data-in-code (undecodable). Producer nằm trong
  đúng loại code này + VM (0x55950).

## Kết luận / bức tường
- Bắt producer-store cần: (a) devirt VM header-builder (multi-week), HOẶC (b) memory-write-watch ARM
  TRƯỚC init — nhưng region-ID khó + Exynos 8890 (SM-G930S) KHÔNG có HW-watchpoint (chỉ SW page-level thô).
- Đây là cùng bức tường project đã gặp, nay khoanh vùng CHÍNH XÁC: header-builder ghi vào struct
  0x7ccc8xxxxx, keyid2B + slot16, trong CFF+VM code.

## Files
- Hooks: `_run_catch_spawn.py`, `_run_spawn.py`, `_slot16_locate.js`, `_slot16_dump.js`, `_slot16_bt.js`,
  `_append_trace.js`, `_slot16_flow.js`, `_producer_catch.js`, `_disasm_live.js`, `_disasm_fn.py`.
- Data: `_pool_fresh.json`, `_flow_out.json`, `_append_out.json`, `_slot16_bt_out.json`, `_disasm_out.json`.
- State (encrypted): `msp_backup_2026-08-25/` (.msp_589c22 1242B, .msp_092f 259B, .mss_9b8e 630B).
