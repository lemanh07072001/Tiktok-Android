#!/usr/bin/env python3
"""Run _vm_trace11.js: spawn app, collect chunked trace, assemble JSONL.
Usage: python3 _run_trace11.py <script.js> [timeout_s]
Line 1 = TRIGGER (marked _meta), following lines = VM dispatch entries in order.
"""
import sys, json, time, frida

PACKAGE = 'com.zhiliaoapp.musically'
JS = sys.argv[1]
TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 45
OUT = JS.replace('.js', '.out.jsonl')
jscode = open(JS).read()

device = frida.get_usb_device()
pid = device.spawn([PACKAGE])
session = device.attach(pid)
script = session.create_script(jscode)

state = {'trigger': None, 'chunks': {}, 'total': 0, 'done': False}

def on_message(msg, data):
    if msg.get('type') == 'send':
        p = msg['payload']; t = p.get('t', '')
        if t == 'info':   print('[*]', p.get('msg'))
        elif t == 'ready':print('[*] hooks installed — waiting for slot16 trigger')
        elif t == 'mon':  print('  [mon] seq=%s dumped=%s' % (p['seq'], p['dumped']))
        elif t == 'TRIGGER':
            print('[TRIGGER] slot16=%s lr=%s x23=%s x24=%s' % (p['slot16'], p['lr'], p['x23'], p['x24']))
            state['trigger'] = p
        elif t == 'TRACE_DUMP':
            state['chunks'][p['idx']] = p['entries']; state['total'] = p['total']
            print('  [chunk] idx=%d +%d / %d' % (p['idx'], p['count'], p['total']))
        elif t == 'done':
            print('[done] total=%d sent=%d' % (p['total'], p['sent'])); state['done'] = True
        else:
            print('[MSG]', p)
    elif msg.get('type') == 'error':
        print('[JS ERROR]', msg.get('description', ''))
        if 'stack' in msg: print('  ', msg['stack'])

script.on('message', on_message)
script.load()
device.resume(pid)
print('[*] waiting up to %ds...' % TIMEOUT)
deadline = time.time() + TIMEOUT
while time.time() < deadline and not state['done']:
    time.sleep(0.3)

with open(OUT, 'w') as f:
    if state['trigger']:
        tr = dict(state['trigger']); tr['_meta'] = 'TRIGGER'
        f.write(json.dumps(tr) + '\n')
    n = 0
    for idx in sorted(state['chunks']):
        for e in state['chunks'][idx]:
            f.write(json.dumps(e) + '\n'); n += 1
print('[*] wrote %s  (trigger=%s, entries=%d)' % (OUT, bool(state['trigger']), n))
try: session.detach()
except Exception: pass
