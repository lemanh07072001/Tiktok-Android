> ⚠️ **CORRECTED BY note 71 (2026-09-05).** After the QUIC key-extraction wall was broken,
> the plaintext wire shows get_seed rides a **DEDICATED host `mssdk22-normal-alisg.tiktokv.com`
> (34.107.238.235:443)** over HTTP/3 — NOT "multiplexed on api22 with no mssdk host". The §verdict
> below was an SNI-only (pre-key) misread. The rest of note 70 (tcpdump-below-anti-tamper method,
> QUIC-Initial decode, "wire is 1-RTT AEAD / keys not captured") stands; note 71 supplies the keys.

# 70 — get_seed RAW WIRE: kernel-capture + QUIC-Initial SNI decode → DEFINITIVE map

**Task (user):** "Đào raw wire (Ghidra svc-hunt)" — lấy datagram thô của get_seed, vượt tường
inlined-svc anti-tamper + mssdk-crypto. Đây là "ẩn số duy nhất còn lại" mà BOARD (phiên trước)
đã đánh dấu low-value sau khi get_seed CONTENT đã được giải mã (store-write hook 0x10bbd0 →
`ground-truth/getseed_fresh_ce0516_DECODED.json`).

## 1. Tường svc-hunt (Ghidra/Frida) — ĐÃ CHỨNG MINH KHÔNG ĐI ĐƯỢC
- libmetasec_ov.so chứa **188 inlined `svc #0`** (khớp memory `store-io-inlined-svc-antitamper`).
  Scanner: `scripts/_svc_scan.py` (raw byte-pattern `01 00 00 D4` + per-word backward decode);
  offsets → `scripts/_svc_all_offs.json` (range 0x4de70..0x17a238). Syscall-nr network là
  table-driven (adrp+ldr, PC-trick gadget), KHÔNG phải immediate ⇒ không resolve tĩnh được.
- **Frida Interceptor.attach lên svc = CRASH app.** Đối chứng khoa học:
  0 hook = app sống + tick (`_svc_test0.py`); 5 svc hook = app chết, hết tick (`_svc_test5.py`,
  `_svc_resolve.py`). Đây là hiện thực hoá "blanket svc-hook kills app" (anti-tamper).
  ⇒ Không hook được svc để đọc x8/args tại runtime.

## 2. Giải pháp: tcpdump KERNEL-LEVEL (dưới tường anti-tamper) — THÀNH CÔNG
- `scripts/gscap.sh` (push /data/local/tmp): force-stop + **full-clear mssdk state**
  (`rm -rf files/.msdata/mssdk/ov` + `rm keva/repo/mssdk/*`) → tcpdump wlan0 (PF_PACKET tap,
  DƯỚI app, 0 hook, 0 crash) → cold-start (monkey) → 45s + /proc/net snapshots.
- Artifact: `ground-truth/getseed_wire/gs.pcap` (5.08MB, 5303 pkt) + `gs.sslog` (endpoint attrib).
- get_seed CHẠY trong capture này: store regen (mssdk.blk/chk, .msp_092fde…, .msf3_…) — khớp
  BOARD prior "full-clear+net ⇒ server round-trip PROVEN (dyn_version 2→5 server-bumped)".

## 3. Giải mã toàn bộ transport (parser thuần Python, không lib mạng)
Tool: `scripts/_pcap_census.py` (flow census), `_pcap_sni.py` (TLS SNI),
`_quic_sni.py` (**IETF QUIC Initial decrypt → SNI**, dùng pycryptodome AES-ECB header-prot +
AES-GCM payload, HKDF thủ công, salt draft-29 `afbfec…` / v1 `38762c…`). SNI ra toàn hostname
TikTok thật ⇒ crypto ĐÚNG.

### Bản đồ endpoint đầy đủ (t0 = giây kể từ pkt đầu)
| proto | host (SNI giải mã) | IP | t0 | tx/rx | ghi chú |
|---|---|---|---|---|---|
| QUIC d29 | **api22-normal-c-alisg.tiktokv.com** | 34.102.164.249 | 5.24 | 76K/438K | **API chính — carrier get_seed** |
| QUIC d29 | api22-core-c-alisg | 34.117.67.69 | 5.23 | 14K/167K | core API |
| QUIC d29 | search22-normal-c-alisg | 34.107.238.235 | 5.66 | 2K/5K | |
| QUIC d29 | oec22-normal-alisg | 34.96.106.127 | 5.67 | 24K/122K | |
| QUIC v1 | p16-oec-common-useast2a.ibyteimg.com | 23.202.89.74 | 5.69 | 2K/7K | ảnh |
| QUIC d29 | log22-normal-alisg | 34.128.178.61 | 5.70 | 34K/7K | telemetry (tx-heavy) |
| QUIC d29 | webcast22-normal-c-alisg | 34.54.11.188 | 5.70 | 19K/14K | |
| QUIC v1 | oec16-normal-alisg | 23.202.89.65 | 8.28 | 2K/5K | |
| QUIC d29 | bsync31-normal-alisg | 71.18.231.251 | 8.80 | 40K/267K | |
| QUIC v1 | sf19-teko.tiktokcdn.com | 199.232.234.73 | 43.09 | 8K/603K | CDN |
| gQUIC Q043 | v31-vn-fpt.tiktokcdn.com | 139.177.243.248 | 7.64 | 13K/**2.3M** | **video CDN** (không phải mssdk!) |
| TLS | tnc0/oec22/webcast-frontier/libra32/cp-rp16/vcs-sg/appsflyer/v3.tiktokcdn | … | … | … | phụ trợ |

## 4. KẾT LUẬN ĐỊNH DANH DƯƠNG TÍNH
1. **KHÔNG có host mssdk riêng** (không `mssdk*.tiktokv.com`, không `-va`). get_seed/device_register
   được **multiplex trên API chính** = `api22-normal-c-alisg.tiktokv.com` (34.102.164.249) qua
   **IETF QUIC draft-29**. (Sửa lại mental-model "mssdk raw-socket riêng" — thực chất là QUIC tới API.)
2. `0d3dc86d…"Q043"` (139.177) = **gQUIC video CDN**, KHÔNG phải kênh get_seed (đã loại nhầm trước đây).
3. Payload get_seed trên wire = **QUIC 1-RTT AEAD** (TLS1.3 over QUIC). Ta bắt được Initial (giải SNI)
   nhưng **KHÔNG có khoá 1-RTT** ⇒ bytes ứng dụng **mờ**. Khớp chính xác kết luận elimination cũ
   "get_seed = QUIC internal-AEAD, vô hình với SSL_write (TCP boringssl)".
4. get_seed là **1 stream trong nhiều** bên trong flow api22-normal (rx438K = feed + register trộn),
   không tách riêng được nếu không giải mã QUIC.

## 5. Để đọc được PLAINTEXT wire (nếu muốn) — tường mới, tách biệt
QUIC 1-RTT key-extraction: hook nơi cronet/TTQuicHe boringssl **dẫn xuất traffic secret** →
xuất SSLKEYLOGFILE → giải mã pcap bằng tooling chuẩn. Là sub-project riêng.
**Giá trị thấp:** get_seed CONTENT (dyn_seed/kiid/rtk2_ms trio/server_tsp_diff/schedule_interval)
**ĐÃ có** qua store-write hook (getseed_fresh_ce0516_DECODED.json). Giải mã wire chỉ tái tạo cái đã có,
và dyn_seed không nằm trên đường offline-772. ⇒ human decision, không tự động.

## VERIFY
- pcap parse lại reproducible: `python scripts/_pcap_census.py`, `_quic_sni.py` (SNI = hostname thật).
- Không rò secret: toàn bộ output là hostname/IP công khai; content secret ở artifact redacted riêng.
