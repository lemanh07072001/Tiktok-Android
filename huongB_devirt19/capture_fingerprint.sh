#!/usr/bin/env bash
# capture_fingerprint.sh — capture vân tay session (store + keva) từ phone -> harness.
# Sau đó ký x-argus OFFLINE với vân tay đó (không cần phone).
#   1. (tùy chọn) đặt vân tay giả: bash fakedev.sh pixel6
#   2. bash capture_fingerprint.sh    # dump store+keva -> harness rootfs + psk_triplet
#   3. ký offline: xem sign_offline.sh
set -e
PKG=com.zhiliaoapp.musically
HARNESS=e:/tiktok_signer/regbox/server/unidbg
NS=d8b674543fc0b023b69f6a3f5a0f287d458ea204
STORE="$HARNESS/target/rootfs/default/data/data/$PKG/files/.msdata/mssdk/ov"
STORE2="$HARNESS/target/rootfs/default/data/data/$PKG/files/mssdk/ov"
run(){ MSYS_NO_PATHCONV=1 adb shell "su -c '$1'" 2>&1; }

echo "[1] dump .msp/.mss store (native encrypted state)..."
mkdir -p "$STORE" "$STORE2"
run "cd /data/data/$PKG/files/.msdata/mssdk/ov/ && for f in .ms*; do [ -f \"\$f\" ] && echo FILE:\$f && base64 \"\$f\" && echo ENDFILE; done" > /tmp/_store.txt
python3 - "$STORE" "$STORE2" <<'PY'
import base64,re,sys,os
txt=open('/tmp/_store.txt',encoding='utf-8',errors='replace').read()
n=0
for name,b64 in re.findall(r'FILE:(\.ms\S+)\n(.*?)\nENDFILE',txt,re.S):
    try:
        d=base64.b64decode(b64.strip().replace('\n',''))
        for s in sys.argv[1:]: open(os.path.join(s,name),'wb').write(d)
        n+=1
    except: pass
print(f"    {n} store files")
PY

echo "[2] dump keva triplet (sdi/ecneuq/semithc)..."
run "base64 /data/data/$PKG/files/keva/repo/$NS/$NS.blk" | python3 -c "
import sys,base64,re
d=base64.b64decode(sys.stdin.read().strip().replace('\n',''))
out=[]
for n in ['sdi','ecneuq','semithc']:
    p=d.find(('1233-0-1-'+n).encode())
    m=re.search(rb'\x81([0-9a-f]+)',d[p:p+60]) if p>=0 else None
    if m: out.append(f'{n}={m.group(1).decode()}')
open('$HARNESS/psk_triplet.properties','w').write('\n'.join(out)+'\n')
print('    triplet:', ' '.join(out) if out else 'EMPTY')
"
echo "[*] xong. Vân tay session -> harness. Ký offline: bash sign_offline.sh <url> <ts>"
