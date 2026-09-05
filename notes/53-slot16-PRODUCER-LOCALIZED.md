# 53 — slot16 PRODUCER LOCALIZED (live Stalker ↔ host objdump, 1-1 match)

> 🔁 **SUPERSEDED-BY note 55 (audit 2026-09-04):** claim trung tâm 'producer = custom 64-round compression @0xa0748' **BỊ BÁC** — 0xa0748 = **STANDARD SM3** (verify 3 cách, pure-Node _sm3.js): nó là digest #19, CONSUMER của slot16; 64 'custom rounds'/3×256B tables = SM3 machinery; store 0xa0f90 bắt được = SM3 scratch (input window adjacency). Producer thật = OLLVM-CFF registry lookup (55 + Ghidra). Methodology Stalker §4 (exclude-others, causal value→PC map) vẫn reuse được.

**Ngày:** 2026-08-27 · **AI:** claude · **Task:** route H, option B (reader-anchored single-pass Stalker)
**Kết quả:** ✅ **DONE localization** — producer PC + cấu trúc thuật toán đã ghim, verify chéo.

---

## 1. Producer coordinates (offset trong libmetasec_ov.so; sha1 a9c74e4f…)

| Vùng | Offset | Vai trò |
|---|---|---|
| Entry (prologue) | **0xa0748** | `stp x28,x27,[sp,#-0x60]!` … `sub sp,sp,#0x320` (frame 0x320) |
| `mov x9, x0` | 0xa0774 | **x9 = arg0 = buffer OUTPUT** |
| Input marshalling | 0xa0748 … ~0xa0e40 | **ret-trampoline CFF** (`adr x4,next; mov x30,x4; ret`) + dựng hằng trên stack (`w12=0x79cc4519`, `str w12,[sp]…`). Khó đọc tĩnh. |
| **Loop A (schedule)** | **0xa0e40** | `cmp #0x10` → **16 vòng**; nạp **3 bảng 256B** trên stack: `x6=sp`, `x7=sp+0x100`, `x19=sp+0x200` |
| set table ptrs | 0xa0ecc–0xa0ed4 | `mov x6,sp; add x7,sp,#0x100; add x19,sp,#0x200` |
| **Loop B (compress)** | **0xa0ed8** | `cmp #0x40` → **64 vòng**; đọc bảng `[x6/x7/x19, x27]`, `x27 = round<<2` |
| whitening | 0xa0f70–0xa0f8c | 8× `eor w16..w8` |
| **STORE output** | **0xa0f90–0xa0f9c** | 4× `stp {w16,w17,w15,w14,w13,w12,w11,w8}, [x9,#0x8..0x28]` (**32 byte**) |
| stack-guard + epilogue | 0xa0fa0–0xa0fcc | canary check, restore, `ret` |

→ slot16 (16B) = **cửa sổ 16 byte** trong khối 32 byte `[x9+0x8 .. x9+0x28]`, sau đó copy sang pool `0x77e4…`, đọc lại bởi memcpy `0xa0440` (`x19=pool ptr` — note 48).

## 2. Thuật toán (custom compression kiểu SHA, KHÔNG phải ARX thuần)

- **ARX ops:** `add w`, `eor w`, rotate hằng `ror #13/#20/#25/#23/#15`, **rotate biến** `ror wX, wX, neg(w0)` (phụ thuộc round).
- **Choose (CH) kiểu SHA:** `and w26,w3,w22; bic w27,w21,w22; orr w26,w27,w26` = `(w3 & w22) | (w21 & ~w22)`.
- **MAJ-ish:** `orr w5,w20,w24; and w25,w20,w24` … kết hợp.
- 3 bảng schedule 256B (=64 word mỗi bảng) index theo round → message/key schedule expand từ PSK(32B)+seed(4B).

## 3. Bằng chứng verify (live ↔ static, độc lập)

- **Live (Stalker, `_stalk_producer.js`):** STORE_HIT `off 0xa0f9c mnem stp` tại scratch **stack** `0x74fa8a0d90`, val `d703e48e4d48c883|83c41c60be9c6bfe`.
- **Read (memcpy 0xa0440):** slot16 ord1 = `83c41c60be9c6bfe|3ecb9bcedc71ceb2`.
- Nửa 8-byte `83c41c60be9c6bfe` **trùng** (xác suất ngẫu nhiên ~2⁻⁶⁴) → store scratch chính là nguồn slot16.
- **Static (objdump host):** đúng vùng đó là vòng nén 64-round + store 32B → epilogue. Khớp hoàn toàn.
- ARX chạy trên **STACK** (`0x74fa…`), không phải pool (`0x77e4…`) → vì thế mọi filter pool-band trước đó (MAM producer5–12) không thể thấy — **đó là lý do MAM cạn**.

## 4. Cách khắc phục các tường trước đó (đóng góp phương pháp)

1. **Stalker follow crash** (null-deref trong nterp): libmetasec **gọi ngược Java** (`CallStaticObjectMethodV → ms.bd.o.k.b`) giữa lúc ký. Fix = `Stalker.exclude()` MỌI module ≠ libmetasec (398 range) → JNI-callback chạy native, Stalker chỉ instrument libmetasec. **Không còn crash.**
2. **Match sai chiều nhân quả:** so store-value với `wanted` lúc store (trước khi biết slot16). Fix = map `value→PC` cho mọi store dày, tra ở reader (store-then-read).
3. **Producer ở scratch, không ở pool:** bỏ filter pool-band → instrument store dày ở bất kỳ đâu trong libmetasec → lộ vùng `0xa0f90`.
4. Filter stack-spill (`base ∈ {sp,fp}`) + `looksLikeSlot16` (loại mostly-zero) để giảm callout.

## 5. Phase kế (LIFT đầy đủ → pure-node) — kế hoạch hybrid

Marshalling đầu vào bị CFF ret-trampoline → **không devirt tĩnh thủ công** (tốn, dễ sai). Thay vào đó, dùng chính Stalker (đã chạy ổn):

- **Dump tại Loop A entry (0xa0e40):** trạng thái thanh ghi ban đầu + input (PSK 32B, seed 4B) — nguồn của schedule.
- **Dump tại Loop B entry (0xa0ed8):** nội dung 3 bảng schedule (3×256B) trên stack (`sp/sp+0x100/sp+0x200`).
- **Dump tại store (0xa0f90):** output 32B ↔ ghép cặp (input → output) ground-truth.
- **Reimplement lõi SẠCH** (Loop A schedule + Loop B compress + slice) bằng node, **diff** với cặp thật.
- PSK cố định, chỉ seed(4B) đổi mỗi request → đặc tả bảng phụ thuộc seed để sinh slot16 cho seed bất kỳ (mục tiêu no-phone).

## 6. Artifacts
- `_stalk_producer.js` — Stalker producer-localizer (exclude-others + causal map + no-band). Tái dùng cho phase dump.
- `notes/_producer_disasm_a0000-a1000.txt` — disasm host quanh producer (1030 dòng).
