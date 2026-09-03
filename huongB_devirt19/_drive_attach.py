#!/usr/bin/env python3
# Path A oracle DRIVER — ATTACH-after-launch (evades spawn-time anti-frida).
# Launch app normally -> anti-tamper passes -> attach -> load oracle ->
# drive store I/O by scrolling -> dump captured store key/iv/ciphertext.
import frida, subprocess, sys, time, json, os

PKG='com.zhiliaoapp.musically'
ADB=os.path.expanduser('~/Library/Android/sdk/platform-tools/adb')
SCRIPT='_store_key_grab.js'
OUT='_grab_out.json'
COLLECT=45      # seconds of live collection
SWIPE_EVERY=4   # scroll interval

def sh(*a):
    return subprocess.run([ADB,*a],capture_output=True,text=True,timeout=60)

def pidof():
    r=sh('shell','pidof',PKG)
    p=r.stdout.strip().split()
    return int(p[0]) if p else None

msgs=[]
def on_msg(m,data):
    if m.get('type')=='send':
        p=m['payload']; msgs.append(p)
        t=p.get('tag')
        if t in ('READY','BOOT','RDR','EINIT') or (t=='KSCH' and p.get('win')):
            print('  <<',json.dumps(p)[:160])
    elif m.get('type')=='error':
        print('  !! script error:',m.get('description'))

# 1. clean launch (normal, no frida) so anti-tamper init passes
print('[*] force-stop + normal launch ...')
try:
    sh('shell','am','force-stop',PKG)
except Exception as e:
    print('  (force-stop slow, continuing):',e)
time.sleep(1)
sh('shell','monkey','-p',PKG,'-c','android.intent.category.LAUNCHER','1')
print('[*] waiting 6s for init + anti-tamper to settle ...')
time.sleep(6)

pid=pidof()
if not pid:
    print('[!] app not running after launch'); sys.exit(1)
print('[*] pid =',pid)

dev=frida.get_usb_device(timeout=10)
print('[*] attaching (NOT spawn) ...')
sess=dev.attach(pid)
scr=sess.create_script(open(SCRIPT).read())
scr.on('message',on_msg)
scr.load()
print('[*] script loaded; driving store I/O for %ds ...'%COLLECT)

t0=time.time(); nexts=0
while time.time()-t0 < COLLECT:
    if time.time()-t0 >= nexts:
        # scroll feed -> signed requests -> store reads
        sh('shell','input','swipe','540','1500','540','400','150')
        nexts+=SWIPE_EVERY
    time.sleep(0.5)

try:
    log=scr.exports_sync.dump()
except Exception as e:
    print('[!] dump failed:',e); log=msgs
json.dump(log,open(OUT,'w'),indent=1)

# summary
tags={}
for e in log: tags[e.get('t') or e.get('tag')]=tags.get(e.get('t') or e.get('tag'),0)+1
print('[=] events:',tags)
rdr=[e for e in log if (e.get('t')=='RDR')]
ksch_win=[e for e in log if e.get('t')=='KSCH' and e.get('win')]
einit_win=[e for e in log if e.get('t')=='EINIT' and e.get('win')]
print('[=] store RDR:',len(rdr),' KSCH in-window:',len(ksch_win),' EINIT in-window:',len(einit_win))
for e in rdr[:6]: print('    RDR',e.get('store'),'len',e.get('len'))
for e in ksch_win[:6]: print('    KSCH-win keyBytes',e.get('keyBytes'),'uk',e.get('userKey'))
for e in einit_win[:6]: print('    EINIT-win keyBytes',e.get('keyBytes'),'uk',e.get('userKey'),'iv',e.get('iv'))
print('[=] wrote',OUT)
sess.detach()
