import sys,json,time,frida,subprocess,re
PKG='com.zhiliaoapp.musically'; JS=sys.argv[1]; SECS=int(sys.argv[2]) if len(sys.argv)>2 else 40
code=open(JS).read()
def sh(*a):
    try: return subprocess.run(['adb','shell',*a],timeout=8,capture_output=True,text=True)
    except Exception as e: print('[sh err]',e)
r=sh('ps','-A'); pid=None
for ln in (r.stdout or '').splitlines():
    parts=ln.split()
    if parts and parts[-1]==PKG: pid=int(parts[1]); break
if pid is None: print('[!] no pid'); sys.exit(1)
print('[*] attach pid',pid,flush=True)
dev=frida.get_usb_device(); sess=dev.attach(pid); sc=sess.create_script(code)
def on(m,d):
    if m.get('type')=='send': print(json.dumps(m['payload']),flush=True)
    elif m.get('type')=='error': print('[JS ERR]',m.get('description'),flush=True)
sc.on('message',on); sc.load()
# IMMEDIATE background->foreground to fire resume heartbeat inside survival window
print('[*] HOME then re-foreground to force heartbeat',flush=True)
sh('input','keyevent','KEYCODE_HOME'); time.sleep(1.2)
sh('am','start','-n',f'{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity'); 
t0=time.time(); n=0
while time.time()-t0<SECS:
    time.sleep(1.5)
    if n==4:  # second bg/fg cycle mid-window
        sh('input','keyevent','KEYCODE_HOME'); time.sleep(1.0)
        sh('am','start','-n',f'{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity')
    n+=1
sess.detach(); print('[*] done')
