import sys, frida, time, json
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1]; T=int(sys.argv[2]) if len(sys.argv)>2 else 40
OUT=JS.replace('.js','.out.jsonl'); open(OUT,'w').close()
dev=frida.get_usb_device(timeout=5); pid=dev.spawn([PKG]); sess=dev.attach(pid)
scr=sess.create_script(open(JS).read())
def on(m,d):
  if m.get('type')=='send':
    p=m['payload']; t=p.get('t')
    if t=='PATH': print('[PATH] fd=%s %s'%(p['fd'],p['path'])); open(OUT,'a').write(json.dumps(p)+'\n')
    elif t=='GLOBAL': print('[GLOBAL]',json.dumps(p['info'] if 'info' in p else p)); open(OUT,'a').write(json.dumps(p)+'\n')
    elif t=='ready': print('[*] ready')
    else: print('[MSG]',p)
  elif m.get('type')=='error': print('[JSERR]',m.get('description'))
scr.on('message',on); scr.load(); dev.resume(pid)
print('[*] up to %ds'%T); dl=time.time()+T
while time.time()<dl: time.sleep(0.5)
sess.detach(); print('[*] detached ->',OUT)
