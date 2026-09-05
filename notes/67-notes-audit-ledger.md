# 67 — Notes audit ledger (2026-09-04, claude)

**Task (user):** decode #24 (test trước khi kết luận) + rà soát TOÀN BỘ notes — cái nào không đứng thì xoá/update.

**Phương pháp:** 4 reader GLM song song (nhóm 00-24 / 25-40 / 41-55 / 56-66), đối chiếu từng note với bộ anchor chuẩn:
notes/55 (slot16 terminal negative + #24=dyn_seed), notes/64 (nguồn đính chính #24), notes/65 (no content-validation), notes/66 (ceiling map + §7 #24 decode), memory (store families, 0xa0748=SM3, bias 0x9b374, box Windows mất).

**Kết quả áp dụng:** 61/61 note được phán. **27 UPDATE + 13 SUPERSEDED banner** đã chèn ngay sau H1 (grep `audit 2026-09-04` để thấy). **21 KEEP nguyên.** **0 note bị xoá** — mọi note đều còn giá trị trail điều tra (kỹ thuật/dữ liệu gốc) nên đính chính bằng banner + pointer thay vì delete, tránh gãy liên kết chéo giữa các note.

## 1. Ba cụm sai lấn lớn nhất được đính chính

1. **"#24 = Widevine MediaDrm/TEE attestation"** (bắt nguồn note 24 W8 → notes 30 T7b, 32, 46, 58, 60, 61, 62, 63) — **SAI toàn tuyến**: #24 = **dyn_seed** (blob opaque server-issued từ get_seed; 132-char b64 → 98B, prefix `30 31`, không phải protobuf lồng; MediaDrm DUID 44-char chỉ là request-side signal). Xem notes/66 §7 (4 corroborations).
2. **"ec7 = attestation/hardware/PIF"** (notes 11, 14, 15, 20, 21, 22, 23, 24-chốt-cuối, 25-interlude) — bị thay bằng **device reputation/velocity + fingerprint-forge bản chất** (note 24 W12-W17, note 65).
3. **"slot16 = hash-derived / pure-offline khả thi"** (notes 39-unicorn, 40-BREAKTHROUGH, 42, 43, 45 §8-12, 47, 51, 53) — bị note 55 chốt tận gốc: slot16 = registry lookup từ device-secret, **pure-offline RULED OUT**, capture-once là đáp án; 0xa0748 = SM3 tiêu chuẩn (consumer).

## 2. Ledger đầy đủ (file → verdict → lý do 1 dòng)

### KEEP (21) — đứng nguyên, không đính chính
| Note | Lý do giữ |
|---|---|
| 00-DESIGN | clean-room spec, nguyên tắc byte-DIFF vẫn là luật |
| 16-body-encoding | enc() XOR 0x05 + x-ss-stub=MD5 đúng |
| 16-device-association | đúng hướng reputation |
| 19-pseudoid-captured | pseudo_id từ response header — SOLVED, anchor |
| 26-nophone-login-2135 | SOLVED, khớp anchor velocity |
| 28-ticket-guard-ts_sign | ts_sign server-issued — đúng |
| 31-dynseed-nophone-SOLVED | note #24=dyn_seed ĐÚNG (anchor) |
| 33-hash19-pskcalhash | #19 = SM3 stock — SOLVED bit-exact |
| 34-slot16-analysis | hypothesis được hedge đúng,_resolve sau |
| 35-cpu-hardware-collection | /sys //proc /ro.* fakeable — đúng |
| 36-xargus-outer-key-CRACKED | envelope cracked — anchor |
| 37-xargus-encoder-SOLVED | encoder bit-exact — anchor |
| 38-slot16-three-walls | kết luận khớp capture-once |
| 39-trackA-killgate | verdict STOP Track A — đúng |
| 48-AVD-HWwatchpoint | read-path cross-device xác nhận (1 claim phụ do 49 tinh chỉnh, không cần banner) |
| 55-slot16-producer-SIGNKEY | terminal negative — anchor |
| 56-msp-static-decrypt | .msp=RC4/.msf3=XXTEA/.mss=AES — anchor |
| 57-mss-dbengine | đúng (.mss không phải signer-dep) |
| 64-field24-source-conflict | chính là nguồn đính chính #24 |
| 65-xargus-content-validation | anchor no-content-validation |
| 66-offline-772-ceiling-map | ceiling map hiện tại (+§7 decode #24) |

### UPDATE (27) — banner ĐÍNH CHÍNH sau H1
| Note | Sai gì → sửa ra sao |
|---|---|
| 01-PLAN | 45.0.3 → 45.7.3 Mac; tasks đã xong, giá trị lịch sử |
| 10-signing | envelope đã giải bit-exact; "server nhận" không chứng minh chữ ký đúng |
| 11-device | "thiếu header client-genuine" → device reputation |
| 14-login | "rate-limit account" chỉ 1 phần → trục chính device reputation |
| 15-validation | "KHÔNG phải device" sai nửa → device-untrusted là trục chính |
| 18-idv-core | cả 2 blocker bị note 19 đập; phần decode đúng |
| 20-device-id | "aging" sai → trusted NGAY khi register sạch; untrust = velocity |
| 21-mssdk-getseed | "112B attestation quyết trust" bị bác; cơ chế get_seed/dyn_seed đúng |
| 23-static-re | D4 "hardware attestation" sai; Harness refs = box đã mất |
| 24-devreg-attestation | 3 chỗ tự-mâu-thuẫn giải theo W13-W17; W8 Widevine = nguồn nhánh sai |
| 25-attestation-genesis | interlude "endpoint STRICT" tự-bác — banner hướng đọc |
| 29-xargus-generic | "wall = collect-thread" stale → EMISSION wall |
| 30-xargus-inner-report | T7b Widevine + row bảng SAI; bảng 35-field vẫn là ground-truth |
| 31-xargus-inner-layout | "dyn_seed KHÔNG phải field report" SAI; "chưa có outer key" bị 36 thay |
| 39-slot16-unicorn-replay | lạc quan "debug hội tụ" bị lật (replay = report-hash, không phải slot16) |
| 40-slot16-characterization | BREAKTHROUGH "pure-offline chắc chắn" bị 55 overrule |
| 45-slot16-F-CONSOLIDATED | §8-12 (interpreter/F=marshaller) chết; §1-7 vẫn là law |
| 46-field24-widevine | PREMISE DISPROVEN toàn note; giữ recipe MSB_* + 0x162dfc |
| 50-VM-dispatch-STATIC | bảng handler = địa chỉ PHANTOM, phải trừ 0x9b374 |
| 52-VM-PROGRAM-MAP | "SHA-256 hash duy nhất" SAI (miss sbox 4-lane, SM3 Tj, SHA1 movk) |
| 54-STORE-DECRYPT | "ALL store = AES" sai 2/3 họ (.msf3=XXTEA, .msp=RC4, .mss=AES) |
| 57-mac-unidbg | khuyến nghị port từ Windows box chết (box mất) |
| 58-consolidated-ledger | row Widevine sai + T10 đã chạy + final-missing bị 66 thay |
| 60-full772-attestation | framing Widevine mislabeled; nửa cơ chế (two-pass inject) vẫn load-bearing |
| 61-state-handoff | title stale (body §2 đã đúng); option (A) Windows chết |
| 62-windows-toolchain | title "#24 SOLVED" sai (DUID ≠ #24); read-slot wall đã giải (63) |
| 63-field24-injected | title mislabel; giá trị inject hiện = stub, đúng phải là dyn_seed 132-char |

### SUPERSEDED-BY (13) — banner pointer, giữ làm trail/data gốc
| Note | Bị thay bởi | Còn giữ được gì |
|---|---|---|
| 17-aaas-webview | 19 | mô hình 3 tầng trust + cơ chế webview |
| 22-error7-investigation | 24 | control-tests A1/A3 |
| 32-genuine-xargus-offline-PLAN | 36/37/63 | license_mus4573, MSB_* harness engineering |
| 36-2A-pure-offline-roadmap | 39-trackA | §0 foundations (restated 38/40) |
| 41-slot16-header-storage | 45 | data layout gốc; ".so packed" bị sửa |
| 42-devirt-vm-crypto-landscape | 45 | methodology replay + handler PCs |
| 43-psk-generation-attack-plan | 55 | kỹ thuật message-diff (lịch sử) |
| 44-slot16-F-blackbox-CLOSED | 45 | PHỤ LỤC BẰNG CHỨNG (bảng loại-trừ nguyên văn vào 45 §3) |
| 47-slot16-nonce-reframe | 55 | §1 bằng chứng giết 45 §8-12; "server chấp nhận slot16 divergent" |
| 49-slot16-producer-AVD | 55 | rotation model, K1/K2=SIGN_KEY halves, tooling warnings |
| 51-CRYPTO-ID-sha1-native | 55 | inventory crypto native (nền cho 54) |
| 53-slot16-PRODUCER-LOCALIZED | 55 | methodology Stalker §4 |
| 59-devirt-pskversion-progress | 61 | derivation log thô |

## 3. Quy tắc đọc notes từ giờ

1. Luôn đọc banner đầu note trước (grep `audit 2026-09-04`).
2. Chuỗi truth hiện tại cho từng storyline: **#24** = 64/66 §7; **slot16** = 45 §1-7 + 55; **envelope** = 36/37; **store** = 56; **ec7/trust** = 24 W12-W17 + 65; **ceiling** = 66.
3. `ground-truth/vm_handler_table_52924.txt` vẫn chứa phantom addresses (chưa regenerate) — mọi địa chỉ handler lấy từ 50-post-bias/51/52.
