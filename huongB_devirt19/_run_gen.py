import sys, frida, time, json
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1]; T=int(sys.argv[2]) if len(sys.argv)>2 else 25
OUT=JS.replace('.js','.out.jsonl'); open(OUT,'w').close()
dev=frida.get_usb_device(timeout=5)
pid=dev.spawn([PKG]); sess=dev.attach(pid)
scr=sess.create_script(open(JS).read())
def on(m,d):
  if m.get('type')=='send':
    p=m['payload']; print('[MSG]',json.dumps(p)[:400]); open(OUT,'a').write(json.dumps(p)+'\n')
  elif m.get('type')=='error': print('[JSERR]',m.get('description'),'|',(m.get('stack') or '')[:200])
scr.on('message',on); scr.load(); dev.resume(pid)
dl=time.time()+T
while time.time()<dl: time.sleep(0.5)
try: sess.detach()
except: pass
print('[*] ->',OUT)
