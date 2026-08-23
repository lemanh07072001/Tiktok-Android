# keva PSK dump — chuẩn bị cho offline nonzero-slot16

## Mục tiêu
Lấy 3 giá trị keva THẬT của device (sdi/ecneuq/semithc) + PSK_state/slot16 sống,
feed vào harness unidbg (`MSB_PSK` / `psk_triplet.properties`) → sign offline ra
slot16 NONZERO thật.

## Chống anti-frida (BẮT BUỘC — xem slot16_findings §16)
App trip SafeMode/SIGSTOP khi attach. Trước khi chạy:
1. frida-server đổi tên + port lạ:
   `adb shell "su -c 'cp /data/local/tmp/frida-server /data/local/tmp/msX; chmod 755 /data/local/tmp/msX; nohup /data/local/tmp/msX -l 0.0.0.0:47119 >/dev/null 2>&1 &'"`
   `adb forward tcp:47119 tcp:47119`
2. Magisk DenyList + Shamiko bật cho com.zhiliaoapp.musically (đã có).
3. Attach vào app ĐANG Ở FEED (không spawn lạnh, không force-stop):
   - mở app tay, vuốt tới feed For You
   - `frida -H 127.0.0.1:47119 -n TikTok -l _keva_dump.js`
   - nếu app tự đóng sau vài giây → gửi SIGCONT loop, hoặc dùng frida-server patched thread-name.

## Cách chạy
```
adb shell am start -n com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity
# chờ vào feed, rồi:
frida -H 127.0.0.1:47119 -n TikTok -l _keva_dump.js | tee keva_out.txt
# vuốt feed / pull-to-refresh để trigger device_register heartbeat (nonzero slot16)
```

## Output → harness
- `{t:'KEVA', ns, entry, val}` — mỗi entry là 1 dòng keva. Lấy val cho
  entry endsWith 'sdi'/'ecneuq'/'semithc' → ghi vào psk_triplet.properties:
  ```
  sdi=<val>
  ecneuq=<val>
  semithc=<val>
  ```
- `{t:'obs', slot16, query}` — slot16 sống (verify offline sign khớp).
- `{t:'CONCAT', a0, a1}` — PSK material 32B (c02f250f-family) để cross-check.

## Feed vào harness
```
cp psk_triplet.properties e:/tiktok_signer/regbox/server/unidbg/
cd e:/tiktok_signer/regbox/server/unidbg
MS_VENDOR=libs_trill/ MS_LIBS=libs_trill MS_SIGN_OFF=0x9ecc0 MS_DISP_OFF=0x11a1e0 \
  MS_LICENSE_FILE=license_mus554.txt MS_REALINIT=1 MS_AID=1233 MSB_KV=1 MSB_INIT2=1 \
  MSB_PSK=1 FIXTIME=<ts_giay> SIGN=1 SIGN_SM3RAW=1 \
  java -Djava.library.path=native -cp "target/classes;$(cat cp.txt)" tt.Harness
# -> [SM3RAW] input phải có query||slot16||0x30 với slot16 KHỚP obs sống
```
