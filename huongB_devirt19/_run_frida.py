#!/usr/bin/env python3
"""Run a Frida JS script on the Android device, spawn the app, and capture output."""
import sys
import time
import json
import frida
import os

PACKAGE = 'com.zhiliaoapp.musically'
JS_FILE = sys.argv[1] if len(sys.argv) > 1 else 'huongB_devirt19/_vm_trace5.js'
OUT_FILE = JS_FILE.replace('.js', '_out.jsonl')
TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 120

print(f"[*] Loading script: {JS_FILE}")
print(f"[*] Output: {OUT_FILE}")
print(f"[*] Timeout: {TIMEOUT}s")

with open(JS_FILE, 'r') as f:
    jscode = f.read()

print(f"[*] Spawning {PACKAGE}...")
device = frida.get_usb_device()
pid = device.spawn([PACKAGE])
session = device.attach(pid)

script = session.create_script(jscode)
out_fp = open(OUT_FILE, 'w')

def on_message(msg, data):
    out_fp.write(json.dumps(msg) + '\n')
    out_fp.flush()
    if msg.get('type') == 'send':
        payload = msg.get('payload', {})
        t = payload.get('t', '')
        if t == 'TRIGGER':
            print(f"\n[!] TRIGGER #{payload['info']['seq']} slot16={payload['info']['slot16']}")
        elif t == 'VM_HANDLER_DUMP':
            print(f"[!] DUMP: {payload['traceLen']} entries, nHdlr={payload['nHdlr']}")
        elif t == 'ready':
            print(f"[*] Script ready: {payload}")
        elif t == 'info':
            print(f"[*] {payload}")
        elif t == 'mon':
            print(f"[mon] nHdlr={payload['nHdlr']} nDrv={payload['nDrv']} ri={payload['ri']}")
        elif t == 'warn':
            print(f"[WARN] {payload}")
        elif t == 'error':
            print(f"[ERROR] {payload}")
    elif msg.get('type') == 'error':
        print(f"[JS ERROR] {msg.get('description', '')}")

script.on('message', on_message)
script.load()

print("[*] Resuming app...")
device.resume(pid)

print(f"[*] Waiting up to {TIMEOUT}s for trigger...")
deadline = time.time() + TIMEOUT
while time.time() < deadline:
    time.sleep(1)

print("[*] Timeout reached, detaching...")
session.detach()
out_fp.close()

# Print summary
print(f"\n[*] Output saved to {OUT_FILE}")
try:
    with open(OUT_FILE, 'r') as f:
        lines = f.readlines()
    print(f"[*] Total output lines: {len(lines)}")
    # Show last few messages
    for line in lines[-5:]:
        print(f"  {line.strip()[:200]}")
except:
    pass