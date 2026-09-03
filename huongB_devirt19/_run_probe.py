#!/usr/bin/env python3
"""Run a Frida JS script, spawn the app, collect output, then detach.

Usage:
  python3 _run_probe.py <script.js> [timeout_seconds]

Outputs JSONL to stdout and saves trace dump to <script>.out.jsonl
"""
import sys, json, time, frida, os

PACKAGE = 'com.zhiliaoapp.musically'
JS_FILE = sys.argv[1]
TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 30

with open(JS_FILE, 'r') as f:
    jscode = f.read()

OUT_FILE = JS_FILE.replace('.js', '.out.jsonl')

print(f"[*] Spawning {PACKAGE}...")
device = frida.get_usb_device()
pid = device.spawn([PACKAGE])
session = device.attach(pid)
script = session.create_script(jscode)

dumped = False
entries = []

def on_message(msg, data):
    global dumped, entries
    if msg.get('type') == 'send':
        p = msg['payload']
        t = p.get('t', '')
        if t == 'info':
            print(f"[*] {p.get('msg', p)}")
        elif t == 'ready':
            print("[*] Hooks installed — waiting for SM3 driver trigger...")
        elif t == 'mon':
            print(f"  [mon] seq={p['seq']} dumped={p['dumped']}")
        elif t == 'TRIGGER':
            print(f"\n[TRIGGER] SM3 driver called!")
            print(f"  slot16 = {p['slot16']}")
            print(f"  lr     = {p['lr']}")
            print(f"  x0     = {p['x0']}")
            print(f"  x1     = {p['x1']}")
            print(f"  x2     = {p['x2']}")
            print(f"  x3     = {p['x3']}")
            print(f"  x22    = {p['x22']}")
            print(f"  x23    = {p['x23']}")
            print(f"  x24    = {p['x24']}")
            with open(OUT_FILE, 'w') as f:
                json.dump(p, f)
                f.write('\n')
            print(f"\n  Trigger saved to {OUT_FILE}")
        elif t == 'TRACE_DUMP':
            print(f"\n[TRACE DUMP] {p['count']} entries")
            entries = p['entries']
            with open(OUT_FILE, 'a') as f:
                for e in entries:
                    json.dump(e, f)
                    f.write('\n')
            print(f"  Trace saved to {OUT_FILE} ({len(entries)} lines)")
            dumped = True
        elif t == 'error':
            print(f"[ERROR] {p}")
        else:
            print(f"[MSG] {p}")
    elif msg.get('type') == 'error':
        print(f"[JS ERROR] {msg.get('description', '')}")
        if 'stack' in msg:
            print(f"  Stack: {msg['stack']}")

script.on('message', on_message)
script.load()
device.resume(pid)

print(f"[*] Waiting up to {TIMEOUT}s for trigger...")
deadline = time.time() + TIMEOUT
while time.time() < deadline and not dumped:
    time.sleep(0.5)

session.detach()
print(f"[*] Detached. Output: {OUT_FILE}")