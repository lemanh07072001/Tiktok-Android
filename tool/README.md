# re/tool — Launcher login hàng loạt (mỗi account 1 cửa sổ CMD)

Đọc `account.txt` + `proxy.txt` → mở **mỗi account 1 cửa sổ CMD riêng** (số cmd = số account),
mỗi cửa sổ chạy login chain và **thành công thì hiện info chi tiết** (follower/following/video/likes…).
Dùng lại `re/src/*.mjs` (Node gọi `signOffline`/oracle trực tiếp — không cần server `/sign`).

## Dùng nhanh

1. Điền `account.txt` — mỗi dòng: `user|pass|email|mailpass`
   (tuỳ chọn thêm device trusted: `|did|iid|openudid|cdid|gaid` → login dễ thành công).
2. Điền `proxy.txt` — mỗi dòng 1 proxy (`host:port:user:pass` hoặc `http://user:pass@host:port`).
   Ghép account↔proxy theo dòng; ít proxy hơn thì xoay vòng.
3. (Khuyến nghị) Mở `config.txt` set `METASEC_ORACLE=http://…` nếu có phone-oracle ký genuine.
4. **Double-click `run.cmd`** (hoặc `node batch.mjs`). Xem trước ghép cặp: `node batch.mjs --dry`.

Mỗi cửa sổ tự chạy → in `✓/✗` từng bước → thành công thì in bảng info + lưu `out/<uid>.json`;
lỗi thì in **đúng bước hỏng + gợi ý**. Cửa sổ giữ mở (Enter để đóng).

**Xếp lưới:** sau khi mở, launcher tự xếp các cửa sổ **5 cửa/hàng** cho gọn (`tile.ps1`, chỉ đụng
cửa sổ của run này). Đổi số cửa/hàng: `PER_ROW=` trong `config.txt`. Tắt xếp: `node batch.mjs --no-tile`
(hoặc `TILE=0`). Console mặc định 50×52 ký tự (đổi `COLS`/`LINES`).

## Device riêng theo account (bền)

Mỗi account có **device_id riêng + BỀN**: lần đầu tự `register` device mới rồi lưu
`re/tool/devices/<user>.json`; lần sau **tái dùng đúng device đó** (không đăng ký lại → giữ trust,
tránh bị cờ vì đổi device). Mỗi CMD = 1 account = 1 device riêng, khác nhau hoàn toàn (did/openudid/cdid).
Fingerprint (model/brand/res) cũng **ổn định riêng theo account** (`RE_PROFILE` = hash username).
Muốn dùng device đã mint-trusted sẵn: điền cột `did|iid|openudid|cdid|gaid` ở `account.txt` (ưu tiên hơn file lưu).
Xoá device 1 account (bắt đăng ký lại): xoá file `devices/<user>.json`.

## Các bước 1 account (worker.mjs)

```
02 register_device (hoặc device provided)   06 pre_check
03 dsign + guards (device-token s)          07 user_login → success | 2135
04 seed_cookies (odin_tt)                    08→11 aaas: challenges/send/read_code/verify
05 warmup                                    12 relogin #7 → session_key → INFO
```

Info hiện: nickname · @unique_id · follower · following · video · ❤ nhận (total_favorited) ·
❤ đã thả (favoriting_count) · region · email · has_password. Nguồn: `/aweme/v1/user/profile/self/`
+ `/passport/account/info/v2/` (proven `v2/tests/t_userstats.mjs`).

## Báo lỗi — biết hàm nào hỏng khi TikTok update

`✗ <step>  [LAYER]` + `endpoint` + `http/ec` + `hint`. Ví dụ:
```
✗ user_login  [LOGIN]
    endpoint /passport/user/login/
    http=200  ec=7
    hint: ec7 = velocity/rate-limit theo device_id + IP-register. Mint device IP sạch...
```
`out/fail.txt` gom `user\tstep\tec`.

## Lưu ý quan trọng (giới hạn đã biết)

- **Signer**: Node ký qua `mobile/sign.mjs` (unidbg offline, cần JDK21+maven) HOẶC `METASEC_ORACLE`
  (phone genuine). Login account **cũ** thường **cần X-Argus genuine** mới qua `user/login`
  (note 26); offline chỉ đủ format → có thể ra ec7/2135-loop. Trỏ oracle nếu cần thật.
- **Device trust**: device tự-register (no-phone) thường **untrusted → ec7/1105** ở login.
  Muốn chắc thành công: cấp device đã mint-trusted qua các cột `did|iid|openudid|cdid|gaid` ở `account.txt`.
- **ec7 velocity**: theo IP-register của device + IP login. Dùng proxy residential **sạch**, mỗi account IP riêng.
- Đường dẫn repo **không nên có dấu cách** (launcher truyền path worker trần cho `cmd`).
```
