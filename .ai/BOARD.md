# AI BOARD — cây gậy tiếp sức (relay)

BATON: free            # free | codex | claude | human — ai đang giữ lượt
ROUND: 1               # số lần bàn giao của task hiện tại. ≥6 mà chưa done → BATON: human

---

## Phiếu bàn giao hiện tại

### 2026-08-24 claude → free   STATUS: blocked (recommend pivot to hybrid)

- **Mục tiêu**: Track A devirt VM — ký offline #18/#19
- **Đã làm (phiên này)**:
  * A2.1: Parse A1 capture ✓ — regfile[29] at offset 232-240, ratchet identified
  * A2.2: Bytecode decoder ✓ — decoded 12,914 opcodes from sign_bytecode.bin (103KB)
  * A2.3: op40 handler ✓ — ratchet XOR (0xa123f43) verified working
  * A3: Oracle test ✗ — tested 2 formula variants with op40-ratcheted input vs clean tuple #1: ZERO matches

- **Phát hiện (critical)**:
  * slot16 KHÔNG phải simple HMAC/MD5(PSK, op40_ratchet, query)
  * => Phụ thuộc FULL bytecode execution (12,914 opcodes) không chỉ op40
  * => Cần Unicorn emulation để thực thi bytecode đầy đủ

- **Rào cản Unicorn**: _vm_unicorn_v5.py setup() yêu cầu capture format cụ thể. Integration vào A2 = data format mismatch, rewrite harness = multi-day.

- **Kết luận**:
  * Track A devirt = **2-6 tuần** (full bytecode execution + external state mocks)
  * KILL-GATE HIT (lần thứ 3: B1 fail + A3 fail + Unicorn blocked)
  * **RECOMMEND: Pivot to Hybrid A2** (phone-oracle, ready ngay)

- **Tiếp theo (quyết định người dùng)**:
  * A. Devirt full (Track B/A continuation) → setup Unicorn v5 hợp lý, implement lifter
  * B. Hybrid A2 (practical) → chạy slot16_capture.js, login 1x → capture slot16 per-session
  
---

## Artifacts lưu giữ (Track A research)
- scratchpad/a2_vm_parse.py — A1 capture parser, regfile detector
- scratchpad/a2_vm_dispatch.py — bytecode decoder (12914 opcodes verified)
- scratchpad/a2_vm_ops.py — op40 handler (ratchet XOR logic)
- scratchpad/a3_oracle_simple.py — oracle test framework (2 formulas tested)

<!-- MẪU phiếu, copy khi dùng:
### <YYYY-MM-DD HH:MM> codex → claude   STATUS: blocked
- Mục tiêu: ...
- Đã làm / đã thử: ...
- Việc AI kia cần làm: ...
- File đã đụng: path/a, path/b
- Cách verify: lệnh / diff vs ground-truth nào
STATUS: done | blocked | rework
-->

## Hàng đợi việc (ai cũng thêm được)
- [ ] ...

## Ghi chú
- Nhật ký chi tiết → `STATUS.md` (append). Board này chỉ giữ TRẠNG THÁI HIỆN TẠI + hàng đợi.
- Kẹt = ghi phiếu `blocked` rồi đá baton về, KHÔNG dừng im (xem AGENTS.md §3).
