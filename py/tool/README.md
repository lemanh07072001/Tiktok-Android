# re/py/tool — port Python của `re/tool/` + hàm follow/session

Port 1-1 từ `re/tool/*.mjs` + các script test follow (`re/tests/*.mjs`) sang Python, giữ đúng
convention `re/py/` (signer qua **bridge HTTP** `SIGNER_URL`, `StepError` chỉ đúng bước hỏng, `JAR` cookie thủ công).

## Cần trước
- `SIGNER_URL` (hoặc `METASEC_ORACLE`) trỏ tới cầu ký metasec (`/sign`). Không có → mọi call fail ở bước ký.
- `pip install requests cryptography` (+ `brotli`/`zstandard` nếu server nén).

## Script

| File | Việc | Chạy |
|---|---|---|
| `worker.py` | login-2135 1 account + device BỀN (`devices/<user>.json`) + showInfo + follow tùy chọn | `ACCOUNT="u\|p\|email\|mailpass" python worker.py` |
| `batch.py` | launcher: `account.txt`+`proxy.txt` → mỗi account 1 tiến trình (1 IP) | `python batch.py` \| `--headless` \| `--dry` |
| `follow_flow.py` | LUỒNG FOLLOW: mỗi account login→follow target→verify STUCK/shadow | `python follow_flow.py <target> [1\|0] --acc a.txt --proxy p.txt` |
| `check_follow.py` | nạp session ĐÃ LƯU → follow_status (verify follow thật/shadow, KHÔNG re-login) | `SESSION_FILE=s.json TARGET=idmahg python check_follow.py` |

## Env chính
- `PROXY_URL` — IP egress **mỗi tiến trình 1 cái** (net.py fix proxy theo process → dùng đa tiến trình).
- `FOLLOW=<uniqueId>` `FOLLOW_TYPE=1|0` — worker follow sau login.
- `SAVE_SESSION=<path>` — worker lưu session (dùng lại bằng `check_follow.py`, tránh tốn quota re-verify).
- `NO_PAUSE=1` — không dừng chờ Enter (chạy nền/batch).
- `RE_VER=45.0.3|45.7.3` · `RE_CODE=<code>` (one-shot bỏ đọc mail).

## config.txt (batch.py, KEY=VALUE)
`SIGNER_URL`, `RE_VER`, `STAGGER_MS`. `account.txt`/`proxy.txt` mỗi dòng 1 bản ghi.

## ⚠️ Follow lên thật?
Follow **chỉ đếm** trên **session sạch** (signup non-2135). Session lấy qua login-2135 (mọi account cũ
login device mới) → server nhận GIẢ (`sc=0 follow_status=1`) nhưng re-search về `0` = **shadow-drop vĩnh viễn**
(đã chứng minh). `follow_flow`/`check_follow` báo đúng STUCK vs shadow để biết session có sạch không.
