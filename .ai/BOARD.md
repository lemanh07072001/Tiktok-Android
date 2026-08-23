# AI BOARD — cây gậy tiếp sức (relay)

BATON: free            # free | claude | codex | human — ai đang giữ lượt
ROUND: 0               # số lần bàn giao của task hiện tại. ≥6 mà chưa done → BATON: human

---

## Phiếu bàn giao hiện tại
(trống — chưa có ai bàn giao)

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
