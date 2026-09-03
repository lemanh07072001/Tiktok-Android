import sys, time, json, frida

PID = 11483
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 25
evts = []

def on_msg(m, data):
    if m.get('type') == 'send':
        p = m.get('payload')
        evts.append(p)
        # live echo of the interesting ones
        tag = p.get('tag') if isinstance(p, dict) else None
        if tag in ('READY','RDR','DISP','BENC','BDEC','CBCE','CBCD','EINIT'):
            print('EVT', json.dumps(p)[:200], flush=True)
    elif m.get('type') == 'error':
        print('ERR', m.get('stack','')[:400], flush=True)

dev = frida.get_usb_device(timeout=5)
sess = dev.attach(PID)
with open('_store_oracle.js') as f:
    src = f.read()
scr = sess.create_script(src)
scr.on('message', on_msg)
scr.load()
print('LOADED, collecting %ds ...' % DUR, flush=True)
time.sleep(DUR)
try:
    dump = scr.exports_sync.dump()
except Exception as e:
    dump = evts
    print('dump exc', e, flush=True)
open('_oracle_out.json','w').write(json.dumps(dump, indent=1))
# summary
kinds = {}
for e in (dump or []):
    k = e.get('t') or e.get('tag')
    kinds[k] = kinds.get(k,0)+1
print('SUMMARY', json.dumps(kinds), flush=True)
scr.unload(); sess.detach()
