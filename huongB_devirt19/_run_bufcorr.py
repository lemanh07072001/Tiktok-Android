#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _run_bufcorr.py — run _slot16_bufcorr.js, collect correlated (slot16, query, regfile[29] bufs).
#   python _run_bufcorr.py <PID> [seconds=40] [out=_bufcorr.json]
import sys, os, json, time
import frida

pid = int(sys.argv[1])
dur = int(sys.argv[2]) if len(sys.argv) > 2 else 40
out = sys.argv[3] if len(sys.argv) > 3 else "_bufcorr.json"

js = open(os.path.join(os.path.dirname(__file__), "_slot16_bufcorr.js"), encoding="utf-8").read()
obs = []

def on_msg(m, data):
    if m.get("type") == "error":
        print("[ERR]", m.get("description")); return
    p = m.get("payload") or {}
    if p.get("t") == "info":
        print("[*]", p["msg"], flush=True)
    elif p.get("t") == "obs":
        obs.append(p)
        z = p.get("zero")
        nb = len(p.get("bufs") or [])
        if not z:
            print(f"[obs #{len(obs)}] NONZERO slot16={p['slot16']} bufs={nb} q=...{p['query'][-36:]}", flush=True)
        elif len(obs) % 20 == 0:
            print(f"[obs #{len(obs)}] zero", flush=True)

host = os.environ.get("FRIDA_HOST", "127.0.0.1:47119")
try:
    dev = frida.get_device_manager().add_remote_device(host)
except Exception:
    dev = frida.get_usb_device(timeout=10)
sess = dev.attach(pid)
sc = sess.create_script(js)
sc.on("message", on_msg)
sc.load()
print(f"[*] hooked pid {pid}; {dur}s — browse app (scroll/refresh) to trigger nonzero signs...", flush=True)
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
nz = [o for o in obs if not o.get("zero")]
print(f"\n[*] {len(obs)} obs ({len(nz)} nonzero) -> {out}")
print(f"[*] nonzero with bufs: {sum(1 for o in nz if o.get('bufs'))}")
