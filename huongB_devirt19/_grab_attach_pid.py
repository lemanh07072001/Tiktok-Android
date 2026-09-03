#!/usr/bin/env python3
# Path A oracle driver — ATTACH BY PID (no spawn, no re-register).
# Resilient: waits for a STABLE pid (past crash-loop), retries attach on
# transient TransportError, then drives feed I/O and pulls the full log.
import sys, json, time, subprocess, frida

PKG   = 'com.zhiliaoapp.musically'
ADB   = '/Users/lemanh/Library/Android/sdk/platform-tools/adb'
JS    = '_store_key_grab.js'
OUT   = '_grab_out.json'
SECS  = int(sys.argv[1]) if len(sys.argv) > 1 else 45
SWIPE_EVERY = 3

def adb(*a, t=25):
    try: return subprocess.run([ADB, *a], capture_output=True, text=True, timeout=t)
    except Exception as e: print('  adb err', a, e); return None

def pidof():
    r = adb('shell', 'pidof', PKG)
    s = (r.stdout.strip().split() if r and r.stdout else [])
    return int(s[0]) if s else None

def wait_stable_pid(need=4, gap=3, budget=120):
    """Return a pid seen unchanged for `need` consecutive polls (=settled)."""
    t0=time.time(); last=None; streak=0
    while time.time()-t0 < budget:
        p=pidof()
        if p and p==last: streak+=1
        else: streak=1; last=p
        print(f'  pid poll={p} streak={streak}')
        if p and streak>=need: return p
        time.sleep(gap)
    return last

live=[]
def on_msg(m, data):
    if m.get('type')=='send':
        p=m.get('payload',{}); tag=p.get('tag')
        if tag in ('READY','BOOT'): print('  [js]',tag,p.get('base') or p.get('msg') or '')
        else: live.append(p); print('  [ev]',json.dumps(p))
    elif m.get('type')=='error':
        print('  [JS-ERR]', m.get('stack') or m.get('description'))

print('waiting for stable pid ...')
pid = wait_stable_pid()
if not pid:
    print('!! app not running'); sys.exit(2)
print('stable pid', pid)

dev = frida.get_usb_device(timeout=10)
sess=None
for attempt in range(1,6):
    try:
        p=pidof() or pid
        print(f'attach attempt {attempt} pid {p}')
        sess=dev.attach(p); pid=p; break
    except (frida.TransportError, frida.ProcessNotRespondingError, frida.ServerNotRunningError) as e:
        print('  attach retry:', type(e).__name__, e); time.sleep(3)
if not sess:
    print('!! attach failed after retries'); sys.exit(3)

with open(JS) as f: src=f.read()
scr=sess.create_script(src); scr.on('message', on_msg); scr.load()
print('script loaded; driving', SECS, 's ...')

t0=time.time(); i=0
while time.time()-t0 < SECS:
    time.sleep(SWIPE_EVERY); i+=1
    adb('shell','input','swipe','540','1500','540','400','120', t=15)
    if i%4==0: adb('shell','input','swipe','540','400','540','1500','120', t=15)
    try: st=scr.exports_sync.status()
    except Exception: st=None
    print(f'  t={int(time.time()-t0)}s status={st}')

log=[]
try: log=scr.exports_sync.dump()
except Exception as e: print('dump exc', e)
json.dump(log, open(OUT,'w'), indent=1)
print('=== wrote', OUT, 'events', len(log), '===')

rdr =[e for e in log if e.get('t')=='RDR']
ksw =[e for e in log if e.get('t')=='KSCH' and e.get('win')]
einw=[e for e in log if e.get('t')=='EINIT' and e.get('win')]
blk =[e for e in log if e.get('t') in ('BENC','BDEC','CBCE','CBCD')]
print('RDR store reads   :', len(rdr), sorted({e['store'] for e in rdr}))
print('KSCH in-window    :', len(ksw), [(e['keyBytes'], e.get('userKey')) for e in ksw][:4])
print('EINIT in-window   :', len(einw), [(e['keyBytes'], e.get('userKey'), e.get('iv')) for e in einw][:4])
print('block prims in-win:', len(blk))
try: sess.detach()
except Exception: pass
