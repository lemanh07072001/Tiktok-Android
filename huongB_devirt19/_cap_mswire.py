#!/usr/bin/env python3
# _cap_mswire.py — passive driver for _mswire_crypt.js (notes/73 §5).
# Spawns the app (force-stop first = normal restart), lets it run ~8 min with a
# few benign feed swipes, streams crypt events to cap.noindex/gettoken_crypt/.
# Stdout: tags/sizes ONLY. Secrets (keys/plaintext) land in the git-ignored jsonl.
import frida, sys, time, json, os, subprocess, datetime

DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 480
PKG = "com.zhiliaoapp.musically"
OUT = os.path.join("cap.noindex", "gettoken_crypt")
os.makedirs(OUT, exist_ok=True)
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
jf = os.path.join(OUT, "crypt_%s.jsonl" % ts)
fj = open(jf, "w", encoding="utf-8")

counts = {}
def on_message(msg, data):
    if msg.get("type") == "error":
        print("[JS-ERR]", msg.get("description", "")[:200]); return
    p = msg.get("payload") or {}
    k = p.get("k", "?")
    counts[k] = counts.get(k, 0) + 1
    fj.write(json.dumps(p) + "\n"); fj.flush()
    if k in ("BASE", "ARMED", "WAIT_DLOPEN"):
        print("[%s]" % k, p.get("base", ""))
    elif k == "KS":
        print("[KS] kb=%s key=%s… lr=%s" % (p.get("kb"), (p.get("key") or "")[:8], p.get("lr")))
    elif k in ("ENC", "DEC"):
        print("[%s#%s] len=%s full=%s key=%s… iv=%s… lr=%s" %
              (k, p.get("i"), p.get("len"), p.get("full"), (p.get("key") or "")[:8], (p.get("iv") or "")[:8], p.get("lr")))
    elif k == "RC4":
        print("[RC4#%s] insz=%s" % (p.get("i"), p.get("insz")))

subprocess.run(["adb", "shell", "am", "force-stop", PKG], check=False)
time.sleep(2)
dev = frida.get_usb_device(timeout=10)
pid = dev.spawn([PKG])
session = dev.attach(pid)
script = session.create_script(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                 "_mswire_crypt.js"), encoding="utf-8").read())
script.on("message", on_message)
script.load()
dev.resume(pid)
print("[GO] pid=%s dur=%ss out=%s" % (pid, DUR, jf))

t0 = time.time(); sw = 0
while time.time() - t0 < DUR:
    time.sleep(30)
    el = int(time.time() - t0)
    try:
        st = script.exports_sync.stats()
        print("[%3ds] ks=%s enc=%s dec=%s init=%s rc4=%s drop=%s" %
              (el, st.get("ks"), st.get("enc"), st.get("dec"), st.get("st"), st.get("rc4"), st.get("drop")))
    except Exception as e:
        print("[%3ds] stats err %s" % (el, e)); break
    # benign usage: one feed swipe every ~90s so mssdk keeps reporting
    if sw % 3 == 1:
        subprocess.run(["adb", "shell", "input", "swipe", "540", "1500", "540", "400", "120"], check=False)
    sw += 1

try:
    st = script.exports_sync.stats()
    print("[END]", st)
except Exception:
    pass
fj.close()
print("[OUT]", jf)
print("[COUNTS]", counts)
