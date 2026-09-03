import sys, frida, time, json
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1]; T=int(sys.argv[2]) if len(sys.argv)>2 else 25
OUT=JS.replace('.js','.out.jsonl'); open(OUT,'w').close()
dev=frida.get_usb_device(timeout=5)
# spawn but the app must be far enough to have Java runtime; spawn+resume then attach a moment later is unreliable.
# Instead: spawn, resume, wait, then re-inject via attach to the pid.
pid=dev.spawn([PKG]); dev.resume(pid)
time.sleep(6)  # let ART + app init
sess=dev.attach(pid)
scr=sess.create_script(open(JS).read())
def on(m,d):
  if m.get('type')=='send':
    p=m['payload']; print('[MSG]',json.dumps(p)); open(OUT,'a').write(json.dumps(p)+'\n')
  elif m.get('type')=='error': print('[JSERR]',m.get('description'))
scr.on('message',on); scr.load()
dl=time.time()+T
while time.time()<dl: time.sleep(0.5)
sess.detach(); print('[*] ->',OUT)
