#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# run_slot16_capture.py — load slot16_capture.js into the running TikTok app, collect
# observations into a JSON array the analyzers consume.
#   1) adb shell "su -c '/data/local/tmp/frida-server &'"
#   2) launch app; frida-ps -U | grep -i tiktok   -> PID   (ATTACH by PID; spawn is jailed)
#   3) python run_slot16_capture.py <PID> [seconds] [out.json]
# Then browse the app (scroll/like/login) to trigger signs. Ctrl-C or timeout to stop.
import sys, os, json, time
import frida

if len(sys.argv) < 2:
    print("usage: python run_slot16_capture.py <PID> [seconds=90] [out=slot16_obs.json]")
    sys.exit(2)
pid = int(sys.argv[1])
dur = int(sys.argv[2]) if len(sys.argv) > 2 else 90
out = sys.argv[3] if len(sys.argv) > 3 else "slot16_obs.json"

js = open(os.path.join(os.path.dirname(__file__), "slot16_capture.js"), encoding="utf-8").read()
obs, confirms = [], []


def on_msg(m, data):
    if m.get("type") == "error":
        print("[ERR]", m.get("description"))
        return
    p = m.get("payload") or {}
    t = p.get("t")
    if t == "info":
        print("[*]", p["msg"], flush=True)
    elif t == "confirm":
        confirms.append(p)
        print(f"[confirm #{p['n']}] x0={p['x0']}", flush=True)
        print(f"   struct[0x40]={p.get('struct')}", flush=True)
        print(f"   slot_inline={p.get('slot_inline')}  slot_deref={p.get('slot_deref')}", flush=True)
        print("   ^ verify slot16 = 16 bytes here matches the report #19 tail; else adjust OFF_SLOT.", flush=True)
    elif t == "obs":
        obs.append(p)
        z = (p.get("slot16") == "00" * 16)
        if len(obs) <= 8 or len(obs) % 25 == 0:
            print(f"[obs #{len(obs)}] {'ZERO ' if z else 'NONZERO'} slot16={p.get('slot16','?')[:16]}.. "
                  f"url={(p.get('url') or '')[-40:]} d19={'y' if p.get('d19') else '-'}", flush=True)


dev = frida.get_usb_device(timeout=10)
sess = dev.attach(pid)
sc = sess.create_script(js)
sc.on("message", on_msg)
sc.load()
print(f"[*] hooked pid {pid}; browse the app for {dur}s to trigger signs...", flush=True)
try:
    t0 = time.time()
    while time.time() - t0 < dur:
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
try:
    sess.detach()
except Exception:
    pass
json.dump(obs, open(out, "w"))
nz = sum(1 for o in obs if o.get("slot16") != "00" * 16)
print(f"\n[*] {len(obs)} obs ({nz} nonzero) -> {out}")
print(f"[*] next: python slot16_partition.py {out}   and   python slot16_brute.py {out}")
