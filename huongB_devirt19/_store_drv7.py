import sys, time, json, frida
PID=11483
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 30
def on_msg(m,data):
    if m.get('type')=='send':
        print('EVT', json.dumps(m['payload'])[:260], flush=True)
    elif m.get('type')=='error':
        print('ERR', m.get('stack','')[:400], flush=True)
dev=frida.get_usb_device(timeout=5)
sess=dev.attach(PID)
scr=sess.create_script(open('_store_oracle7.js').read())
scr.on('message',on_msg); scr.load()
print('LOADED7 %ds'%DUR, flush=True)
time.sleep(DUR)
try:
    d=scr.exports_sync.dump()
except Exception as e:
    d={'events':[],'writeBufs':{}}; print('dumpexc',e,flush=True)
json.dump(d, open('_oracle7_out.json','w'), indent=1)
ev=d.get('events',[]); wb=d.get('writeBufs',{})
print('WRITES:',len(ev),'stores_captured:',list(wb.keys()), flush=True)
for e in ev:
    print('  WRITE', e['store'][:36],'n',e['n'],'matched',len(e.get('matches',[])),
          [m['name'] for m in e.get('matches',[])][:4],
          'einit' if e.get('einit') else '', flush=True)
scr.unload(); sess.detach()
