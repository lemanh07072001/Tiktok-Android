import sys, json, time, frida
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1]; TIMEOUT=int(sys.argv[2]) if len(sys.argv)>2 else 45
OUT=JS.replace('.js','.out.jsonl'); open(OUT,'w').close()
dev=frida.get_usb_device(timeout=5); pid=dev.spawn([PKG]); sess=dev.attach(pid)
scr=sess.create_script(open(JS).read())
def on_msg(m,d):
  if m.get('type')=='send':
    p=m['payload']; t=p.get('t','')
    if t in('ready','info'): print('[*]',p)
    elif t=='OPEN':
      print('\n[OPEN] fd=%s path=%s'%(p['fd'],p['path'])); print('   bt:',p['bt'])
      open(OUT,'a').write(json.dumps(p)+'\n')
    elif t in('READ','PREAD'):
      print('[%s] fd=%s nb=%s path=%s'%(t,p['fd'],p['nb'],p['path']))
      print('   data[:64]=%s'%p['data'][:128]); print('   bt:',p['bt'])
      open(OUT,'a').write(json.dumps(p)+'\n')
    else: print('[MSG]',p)
  elif m.get('type')=='error': print('[JSERR]',m.get('description'))
scr.on('message',on_msg); scr.load(); dev.resume(pid)
print('[*] up to %ds...'%TIMEOUT)
dl=time.time()+TIMEOUT
while time.time()<dl: time.sleep(0.5)
sess.detach(); print('[*] detached ->',OUT)
