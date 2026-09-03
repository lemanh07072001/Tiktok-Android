import sys,json,time,frida,subprocess,re
PKG='com.zhiliaoapp.musically'
JS=sys.argv[1]; SECS=int(sys.argv[2]) if len(sys.argv)>2 else 60
code=open(JS).read()
def sh(*a):
    try: return subprocess.run(['adb','shell',*a],timeout=8,capture_output=True,text=True)
    except Exception as e: print('[sh err]',e); return None
# get pid of main app process (exact package, not :sub-processes)
r=sh('ps','-A'); pid=None
for ln in (r.stdout or '').splitlines():
    if ln.rstrip().endswith(' '+PKG) or re.search(r'\b'+re.escape(PKG)+r'$',ln):
        pid=int(ln.split()[1]); break
if pid is None:
    for ln in (r.stdout or '').splitlines():
        if PKG in ln and ':' not in ln.split()[-1]:
            pid=int(ln.split()[1]); break
if pid is None: print('[!] pid not found'); sys.exit(1)
print('[*] attach by pid',pid,flush=True)
dev=frida.get_usb_device()
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
