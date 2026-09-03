import sys, frida, time
PKG='com.zhiliaoapp.musically'
dev=frida.get_usb_device(timeout=5)
# attach to running process if present, else spawn
try:
    procs=[p for p in dev.enumerate_processes() if p.name and 'musical' in p.name.lower()]
except Exception as e:
    procs=[]
if procs:
    pid=procs[0].pid; sess=dev.attach(pid); spawned=False
    print('[*] attached to running pid',pid)
else:
    pid=dev.spawn([PKG]); sess=dev.attach(pid); spawned=True
    print('[*] spawned pid',pid)
scr=sess.create_script(open(sys.argv[1]).read())
def on_msg(m,d):
    print('[MSG]', m.get('payload') if m.get('type')=='send' else m)
scr.on('message',on_msg); scr.load()
if spawned: dev.resume(pid)
time.sleep(2); sess.detach()
