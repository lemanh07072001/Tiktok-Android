import sys, json, time, frida
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1]; TIMEOUT=int(sys.argv[2]) if len(sys.argv)>2 else 40
OUT=JS.replace('.js','.out.jsonl'); open(OUT,'w').close()
dev=frida.get_usb_device(timeout=5); pid=dev.spawn([PKG]); sess=dev.attach(pid)
scr=sess.create_script(open(JS).read())
def on_msg(m,d):
  if m.get('type')=='send':
    p=m['payload']; t=p.get('t','')
    if t in('info','ready'): print('[*]',p)
    elif t=='ENTER':
      print('\n[ENTER #%s] x0=%s x1=%s x2=%s x3=%s'%(p['n'],p['x0'],p['x1'],p['x2'],p['x3']))
      print('   @x0:',p['at_x0']); print('   @x1:',p['at_x1']); print('   @x2:',p['at_x2'])
      open(OUT,'a').write(json.dumps(p)+'\n')
    elif t=='LEAVE':
      print('[LEAVE #%s] ret=%s'%(p['n'],p['ret']))
      print('   @x0_saved:',p['at_x0_saved']); print('   @x1_saved:',p['at_x1_saved']); print('   @ret:',p['at_ret'])
      open(OUT,'a').write(json.dumps(p)+'\n')
    else: print('[MSG]',p)
  elif m.get('type')=='error': print('[JSERR]',m.get('description'))
scr.on('message',on_msg); scr.load(); dev.resume(pid)
print('[*] up to %ds...'%TIMEOUT)
dl=time.time()+TIMEOUT
while time.time()<dl: time.sleep(0.5)
sess.detach(); print('[*] detached ->',OUT)
