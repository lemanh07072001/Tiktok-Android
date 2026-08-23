# AGENTS — luật chung cho 2 AI (Claude Code + Codex CLI)

> File này là **nguồn luật duy nhất**. Codex đọc trực tiếp; Claude đọc qua `CLAUDE.md` (import).
> Chế độ phối hợp: **RELAY (luân phiên)** — mỗi lúc chỉ 1 AI làm, xong thì bàn giao.

## 1. Quy ước project (đã có sẵn — TUÂN THỦ, đừng phát minh lại)
- Kế hoạch task tuần tự: `notes/01-PLAN.md`. Chưa VERIFY xanh = chưa qua task sau.
- Phát hiện → `notes/NN-*.md`. Nhật ký (append mỗi bước) → `STATUS.md`.
- Mọi field/header/body phải truy về capture thật trong `ground-truth/` — **không tưởng tượng**.
- Test = DIFF vs ground-truth, không phải unit test bịa.

## 2. Giao thức RELAY (bắt buộc)
Cây gậy tiếp sức nằm ở `.ai/BOARD.md`.

**Trước khi làm bất cứ gì:**
1. Đọc `.ai/BOARD.md`.
2. Chỉ làm nếu `BATON` = tên bạn **hoặc** = `free`. Nếu là AI kia → DỪNG, không sửa file.

**Khi bàn giao (xong / kẹt / cần AI kia):** cập nhật phiếu trong `.ai/BOARD.md` với `STATUS`:
- `done`  — task xong + đã verify. Ghi cách verify. Đổi `BATON: free` → kết thúc vòng.
- `blocked` — KẸT/đường cùng. Ghi rõ: kẹt ở đâu, đã thử gì (liệt kê), cần AI kia làm gì để gỡ. Đổi `BATON` sang AI kia.
- `rework` — làm rồi nhưng AI kia cần sửa/tiếp. Ghi việc còn lại. Đổi `BATON` sang AI kia.

Mọi lần bàn giao: **tăng `ROUND` +1** và append 1 dòng `STATUS.md` (`YYYY-MM-DD [ai] status: tóm tắt`).

## 3. Kẹt thì KHÔNG bỏ cuộc — bật ngược, lặp đến khi xong
- Đường cùng ≠ dừng im. Luôn ghi phiếu `blocked` (nêu chính xác chỗ tắc + đã thử gì + cần gì) và đá `BATON` về AI kia.
- Vòng lặp claude ↔ codex tiếp diễn cho tới khi có phiếu `STATUS: done`.
- **Chốt chặn chống ping-pong vô tận:** nếu `ROUND ≥ 6` (≈3 lượt/ bên) mà vẫn chưa `done` và không có tiến triển mới → DỪNG, đặt `BATON: human`, ghi phiếu tóm tắt bế tắc + các hướng còn lại, báo người dùng. Đừng đốt vòng lặp khi cả hai bí như nhau.
- Khi đổi task mới: reset `ROUND: 0`.

## 4. Nhận diện
- Claude Code tự xưng `claude`. Codex CLI tự xưng `codex`. Dùng đúng tên này trong BOARD/STATUS.
