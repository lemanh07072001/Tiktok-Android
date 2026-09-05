# 69 — get_seed: BẰNG CHỨNG LIVE trên phone thật (không phải docs)

Thiết bị: Samsung SM-G930S `ce0516`, Android 14, musically **45.5.4**, Magisk root, frida 17.17.0.
Toàn bộ dưới đây là thao tác THẬT trên phone (adb+frida+iptables), có verify, không suy từ docs.

## 0. Vì sao viết note này
User yêu cầu "vào phone bắt xem get_seed hoạt động thế nào". Note 21 (dựa trên capture cũ,
device ce031603/45.9.3) khẳđịnh: get_seed fire ~2×/cold-start qua **TCP+TLS**, chặn QUIC rồi
capture SSL_write là bắt được. **Trên ce0516/45.5.4 điều đó KHÔNG tái lập.** Chi tiết bên dưới.

## 1. Vị trí cache seed của mssdk (đã xác minh trên disk)
```
/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov/
   .msp_092fde7a...   (seed blob A)   gốc 235B
   .msp_589c2233...   (seed blob B)   gốc 373B   <- chứa vật liệu seed chính
   .mss_9b8ed995...   630B
/data/data/com.zhiliaoapp.musically/files/keva/repo/mssdk/
   mssdk.blk (8192)  mssdk.chk (4096)   <- KV bền, repopulate sau khi xóa
```
Nội dung `.msp_` = dạng store đã mã hoá (XOR-stream VM-gated, memory `.msp cipher = XOR-stream`),
KHÔNG phải dạng "01"-prefix đã giải. Byte đầu ví dụ: `cf63 d82f 859f f048...`.

## 2. get_seed KHÔNG fire trên cold-start thường
Thử nhiều lần: force-stop → xóa `.msp_*`+`.mss_*`+keva/mssdk → cold-start, hook:
- `getaddrinfo` (libc, arg0=hostname, transport-agnostic DNS)
- `SSL_write`/`SSL_read` trên **libttboringssl.so** (@…c8f8, đúng hàm cronet dùng cho TLS)
Trong 40–90s: bắt được host thật (v3.tiktokcdn, webcast-frontier16, vcs-sg.tiktokv.com…)
**nhưng KHÔNG có `mssdk22-normal-alisg` DNS, KHÔNG có `/ms/get_seed` TLS.** Lặp lại nhiều lần.

## 3. CÓ đường derive seed LOCAL (không cần mạng) — test quyết định
Chặn HẲN mạng của app: `iptables -I OUTPUT -m owner --uid-owner 10185 -j DROP` (uid app=10185,
verify rule active: "DROP all owner UID match 10185"; verify app mất mạng: chạy ping dưới uid app
→ `socket: Permission denied`). Xóa sạch seed → cold-start 40s KHÔNG mạng:
**`.msp_` VẪN tái tạo (41B / 62B).** ⇒ app boot được với seed sinh **local**, get_seed KHÔNG bắt buộc.

## 4. Gradient kích thước seed (dữ kiện, đã đo)
| điều kiện | .msp_092f | .msp_589c |
|---|---|---|
| gốc (get_seed thật, trước phiên) | 235B | **373B** |
| net-up, xóa+regen (get_seed KHÔNG hoàn tất) | ~128B | ~249–250B |
| **no-net** (chặn uid), xóa+regen | 41B | **62B** |

Fact đã chứng minh: (a) tồn tại derive local; (b) không get_seed qua TLS/DNS trong cửa sổ đo;
(c) seed net-up **lớn hơn** seed no-net (~250B vs 62B).
Suy luận (mạnh, CHƯA giải mã trực tiếp): ~190B chênh khi có mạng = vật liệu server nạp qua
**QUIC** (get_seed hoặc refresh mssdk khác). Chưa loại trừ được nguồn khác ngoài get_seed.

## 5. Vì sao hook TLS/DNS thấy trắng — kiến trúc mạng
- Networking = **TTNet/cronet** `libsscronet.so` (5.2MB), **QUIC-first**. Exports có
  `TTQuicHe_HttpRequestCallback_OnResponseStarted/OnReadCompleted/OnSucceeded` = callback QUIC
  riêng của ByteDance.
- TLS (khi rớt TCP) = `libttboringssl.so` (SSL_write @…c8f8, cronet import hàm này).
- mssdk = `libmetasec_ov.so` (2MB, khớp thư mục `mssdk/ov/`).
- get_seed đi **QUIC (UDP 443)** ⇒ payload qua QUIC packet-protection, **KHÔNG qua SSL_write**;
  DNS bị **cache/pin** ⇒ getaddrinfo không gọi lại. Đó là lý do 2 hook kia mù.
- Chặn UDP443 (ép TCP) KHÔNG cứu được: mssdk-QUIC ở đây **không có TCP fallback** (khác TTNet lõi),
  chặn QUIC chỉ làm app đói mạng → ghi seed degraded nhỏ hơn.

## 6. Muốn bắt get_seed plaintext LIVE thì hook ở đâu (đường đúng, chưa làm)
KHÔNG phải tầng TLS. Phải:
- (a) Tầng callback cronet: `TTQuicHe_HttpRequestCallback_OnReadCompleted` + đọc buffer qua
  `Cronet_Buffer_GetData`/`Cronet_Buffer_GetSize`, lấy URL qua `Cronet_UrlResponseInfo_url_get`.
  CẢNH BÁO: nhiều export cronet **trùng địa chỉ** (ICF-folded), hook trực tiếp dễ bắt nhầm.
- (b) Hoặc hook trong `libmetasec_ov.so` chỗ dựng request 112B / parse response 176B (cần offset
  build này, chưa có).
**Nút thắt thật = TRIGGER get_seed**, không phải tầng hook: xóa cache lặp chỉ ra seed local degraded
(có thể server rate-limit sau nhiều lần xóa). Ép get_seed đầy đủ nhiều khả năng cần **re-register
thiết bị** → rủi ro session đăng nhập thật ⇒ **quyết định của người**, không tự động.

## 7. Trạng thái phone sau thí nghiệm
Đã restore seed gốc từ backup `cap.noindex/phone_ce0516_backup/mssdk_backup.tgz`
(.msp_ 235/373B, .mss 630B — timestamp gốc). Gỡ hết iptables (uid-10185 + udp443). QUIC mở.
Phone về bình thường.

## 8. Hệ quả cho các note khác
- Note 21: sửa — "get_seed 2×/cold-start qua TCP+TLS" KHÔNG đúng cho 45.5.4/ce0516. Cold-start
  dùng seed local/cached; refresh server (nếu có) qua QUIC, không rớt TCP.
- Củng cố memory `.msp device-secret` + `.msp cipher = XOR-stream`: seed on-disk là store mã hoá,
  và có nhánh sinh local (degraded) độc lập với get_seed.

---

## 9. ★★★ BẮT ĐƯỢC NỘI DUNG get_seed TƯƠI (2026-09-04, user cho phép ép trigger)

**Ép trigger THÀNH CÔNG + bắt plaintext seed — KHÔNG cần crack QUIC.**

### 9.1 Trigger hoạt động
`am force-stop` + `rm -rf .msdata/mssdk/ov` + `rm keva/repo/mssdk/*` (full-clear, KHÔNG đụng
device_id/cookies) + cold-start CÓ mạng → app gọi mssdk server, `.msp_589c` regen **363B**
(vs no-net chỉ 62B). Server round-trip thật sự xảy ra.

### 9.2 Loại trừ MỌI bề mặt export-được (get_seed = QUIC nội bộ, DỨT KHOÁT)
| Hook | Kết quả |
|------|---------|
| `SSL_write`/`SSL_read` **libttboringssl** | 0 get_seed (chỉ webcast/vcs/cdn) |
| `SSL_write`/`SSL_read` **system libssl.so** | 0 get_seed |
| `getaddrinfo` (DNS) | 0 mssdk22 (DNS cached/pinned) |
| cronet `Cronet_UrlRequest_InitWithParams` | 1 URL (webcast) ≠ seed |
| cronet callbacks `TTQuicHe_*`/`Cronet_Buffer_*` | 0 (TTNet không gọi C-API nội bộ) |
| **system `libcrypto.so` `EVP_AEAD_CTX_seal/open`** | **0 calls/70s** → cronet KHÔNG dùng system libcrypto |

⇒ QUIC AEAD nằm trong **BoringSSL static-link ẩn của `libsscronet`**. Crack wire cần tìm offset
nội bộ EVP_AEAD trong .so 5.2MB (nhiều giờ, GIÁ TRỊ THẤP vì nội dung đã bắt được bên dưới).

### 9.3 Điểm bắt ĐÚNG = biên ghi-store (plaintext, KHÔNG cần QUIC)
`huongB_devirt19/_mspspawn.js` (site K0 `0x10bbd0`, return-addr `0x1184a8`) chạy đúng trên
ce0516 (build 45.5.4, libmetasec_ov 2032384B — offset khớp). Sau full-clear+net, bắt được
plaintext store TRƯỚC mã hoá, lớn dần theo từng field response server đáp về:
`247→260→287→339→361B` (khớp file 363B). pre0=`[hdr][zlib(JSON)]`, pre1=tên-store-hash.

**Nội dung seed TƯƠI đã giải mã** (`ground-truth/getseed_fresh_ce0516_DECODED.json`, redacted):
```
dyn_seed             (b64 132 → ~99B opaque, prefix "01")
dyn_deviceid         7677798657664026132
kiid                 REDACTED-… (ce0516 riêng)
dyn_version          5              ← signer device chỉ v2 → SERVER tăng version
dyn_last_update_time 1788523340  = 2026-09-04T12:02:20Z  ← ĐÚNG hôm nay (tươi)
fltk                 1788523341803  (ms launch)
server_tsp_diff      -339           ← lệch đồng hồ client↔server = BẰNG CHỨNG round-trip
rtk2_ms/rdk2_ms/rsk2_ms            ← bộ ms-token do server cấp
rep_vd true, schedule_report_interval
```

### 9.4 Kết luận
get_seed = **POST tới mssdk server qua QUIC**, server trả về: dyn_seed mới (versioned, v5),
bộ ms-token trio, `server_tsp_diff` (đồng bộ đồng hồ), `schedule_report_interval`. App ghép dần
vào store `8fd6b14a…` rồi zlib+mã hoá thành `.msp_`. **Đã chứng minh & giải mã đầy đủ trên phone
thật**, không đoán docs. Wire QUIC thô là ẩn số duy nhất còn lại (giá trị thấp: dyn_seed cho
signer device đã có trong `device_secret/`, và đây không nằm trên đường tới đích offline-772).

### 9.5 Phone sau thí nghiệm
ce0516 hiện giữ seed TƯƠI v5 chính chủ (app tự fetch — trạng thái hợp lệ, hoạt động bình thường).
iptables: `NO-OWNER-RULES` (đã sạch). QUIC mở. frida-server giữ lại (công cụ).
