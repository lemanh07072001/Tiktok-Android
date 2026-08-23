# Ký X-Argus OFFLINE với vân tay qua phone (1-capture → ∞-sign)

Kiến trúc: capture vân tay session (store + keva) từ phone 1 LẦN → ký x-argus
OFFLINE với vân tay đó mãi mãi (không cần phone mỗi lần ký).

## Quy trình

### Bước 1 (tùy chọn): đặt vân tay giả trước khi capture
```bash
bash fakedev.sh pixel6    # thiết bị sẽ trình bày là Pixel 6
# force regen store với vân tay mới:
adb shell "su -c 'rm -rf /data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov/* /data/data/com.zhiliaoapp.musically/files/keva/repo/d8b674*/*'"
adb shell am force-stop com.zhiliaoapp.musically
adb shell monkey -p com.zhiliaoapp.musically 1   # cold-start regen
# browse app vài giây để metasec ghi store
```

### Bước 2: capture vân tay -> harness (CẦN phone, 1 lần)
```bash
bash capture_fingerprint.sh
# dump .msp/.mss store + keva triplet (sdi/ecneuq/semithc) -> harness rootfs + psk_triplet.properties
```

### Bước 3: ký OFFLINE (KHÔNG cần phone, ∞ lần)
```bash
bash sign_offline.sh "<url>" <ts>
# -> X-Argus / X-Gorgon / X-Khronos / X-Ladon mang vân tay đã capture
```

## Đã verify
- Vân tay Pixel6 (FakeDev) -> keva semithc=fbb86b3c (đổi theo vân tay) -> store regen
- capture -> harness -> sign_offline: X-Argus tạo ra KHÁC vân tay cũ (§28) = vân tay
  đi vào chữ ký ✓
- X-Argus đổi mỗi lần (nonce nội tại) nhưng X-Khronos=ts, X-Gorgon ổn định theo time.

## Giới hạn (QUAN TRỌNG — đã chứng minh)
- **slot16 nonzero**: x-argus offline này dùng zero-slot16 path (không có slot16 sống).
  #19 report field = zero-slot16. Nếu endpoint cần nonzero slot16 -> phải capture
  slot16 sống thêm (slot16_capture.js, xem SIGN_OFFLINE + compute_hash19).
- **Server-trust**: register/login vẫn ec7 (W13-W17: server tin identity+Play Integrity,
  KHÔNG tin vân tay). Endpoint device_register/dsign/send_code có thể qua. Vân tay giả
  KHÔNG tự tạo trust — chỉ đổi thứ metasec encode.

## Files
- `capture_fingerprint.sh` — dump store+keva phone -> harness
- `sign_offline.sh` — ký x-argus offline
- `fakedev.sh` — (tùy chọn) đặt vân tay giả trước
- Harness block: MSB_PSK (triplet), MS_FILESDIR (store path), MS_SPOOF (proc override)
