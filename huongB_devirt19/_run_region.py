import sys,json,time,frida
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1] if len(sys.argv)>1 else '_p_region_probe.js'
SECS=int(sys.argv[2]) if len(sys.argv)>2 else 45
OUT=JS.replace('.js','.out.jsonl')
code=open(JS).read()
dev=frida.get_usb_device(); pid=dev.spawn([PKG]); print('[*] spawned',pid)
sess=dev.attach(pid); sc=sess.create_script(code); fh=open(OUT,'w'); hits=[0]
def on(m,d):
    if m.get('type')=='send':
        p=m['payload']; t=p.get('t','')
        if t=='info': print('[i]',p.get('msg'))
        elif t=='ready': print('[*] ready')
        elif t=='mon': print('  [mon] trig=%s'%p['trig'])
        elif t=='HIT':
            hits[0]+=1
            print('\n[HIT #%d] slot16=%s P=%s'%(p['n'],p['slot16'],p['P']))
            print('  region=',p['region'])
            print('  bt:')
            for fr in p['bt']: print('     ',fr)
            fh.write(json.dumps(p)+'\n'); fh.flush()
        else: print('[msg]',p)
    elif m.get('type')=='error': print('[JS ERR]',m.get('description'))
sc.on('message',on); sc.load(); dev.resume(pid)
print('[*] waiting %ds...'%SECS); t0=time.time()
while time.time()-t0<SECS: time.sleep(0.5)
sess.detach(); fh.close(); print('[*] done',hits[0],'HITs ->',OUT)
