import sys,json,time,frida,subprocess
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1]; SECS=int(sys.argv[2]) if len(sys.argv)>2 else 60
code=open(JS).read()
def sh(*a):
    try: subprocess.run(['adb','shell',*a],timeout=8,capture_output=True)
    except Exception as e: print('[sh err]',e)
dev=frida.get_usb_device()
pid=None
for p in dev.enumerate_processes():
    if 'musical' in p.name or p.name==PKG: pid=p.pid; print('[*] found',repr(p.name),pid); break
if pid is None: print('[!] not running'); sys.exit(1)
sess=dev.attach(pid); sc=sess.create_script(code)
def on(m,d):
    if m.get('type')=='send': print(json.dumps(m['payload']),flush=True)
    elif m.get('type')=='error': print('[JS ERR]',m.get('description'),flush=True)
sc.on('message',on); sc.load()
print('[*] loaded; driving UI',flush=True)
t0=time.time(); n=0
while time.time()-t0<SECS:
    if n%3==0: sh('input','swipe','540','1700','540','500','160')
    n+=1; time.sleep(2)
sess.detach(); print('[*] done')
