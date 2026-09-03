import sys,json,time,frida,subprocess
PKG='com.zhiliaoapp.musically'
ACT='com.ss.android.ugc.aweme.splash.SplashActivity'
JS=sys.argv[1]; SECS=int(sys.argv[2]) if len(sys.argv)>2 else 60
SETTLE=int(sys.argv[3]) if len(sys.argv)>3 else 14
code=open(JS).read()

def sh(*a): 
    try: subprocess.run(['adb','shell',*a],timeout=8,capture_output=True)
    except Exception as e: print('[sh err]',e)

# natural launch (login persists — NO re-register)
sh('am','force-stop',PKG); time.sleep(1)
sh('am','start','-n',f'{PKG}/{ACT}')
print('[*] launched, settling',SETTLE,'s for feed/login...')
time.sleep(SETTLE)

dev=frida.get_usb_device()
# find running pid
pid=None
for p in dev.enumerate_processes():
    if p.name==PKG or 'musical' in p.name: pid=p.pid; break
if pid is None:
    print('[!] app not running after launch'); sys.exit(1)
print('[*] late-attach pid',pid)
sess=dev.attach(pid); sc=sess.create_script(code)
def on(m,d):
    if m.get('type')=='send': print(json.dumps(m['payload']),flush=True)
    elif m.get('type')=='error': print('[JS ERR]',m.get('description'),flush=True)
sc.on('message',on); sc.load()
print('[*] script loaded; driving UI to trigger heartbeat/signing')

t0=time.time(); nsw=0
while time.time()-t0<SECS:
    # gentle UI drive: swipe up on feed every ~6s to trigger network+signing
    if nsw%3==0: sh('input','swipe','540','1600','540','600','200')
    nsw+=1
    time.sleep(2)
sess.detach(); print('[*] done')
