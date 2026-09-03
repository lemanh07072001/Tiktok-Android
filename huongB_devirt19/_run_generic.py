import sys,json,time,frida
PKG='com.zhiliaoapp.musically'; JS=sys.argv[1]; SECS=int(sys.argv[2]) if len(sys.argv)>2 else 30
code=open(JS).read()
dev=frida.get_usb_device(); pid=dev.spawn([PKG]); print('[*] spawned',pid)
sess=dev.attach(pid); sc=sess.create_script(code)
def on(m,d):
    if m.get('type')=='send': print(json.dumps(m['payload']))
    elif m.get('type')=='error': print('[JS ERR]',m.get('description'))
sc.on('message',on); sc.load(); dev.resume(pid)
t0=time.time()
while time.time()-t0<SECS: time.sleep(0.5)
sess.detach(); print('[*] done')
