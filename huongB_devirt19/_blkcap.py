import frida, subprocess, sys, json, time, threading
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
DUR=float(sys.argv[1]) if len(sys.argv)>1 else 16.0
pid=int(subprocess.check_output([ADB,'shell','pidof','-s',PKG]).strip())
print('pid',pid,flush=True)
JS=r'''
var MET=Process.getModuleByName('libmetasec_ov.so'),mb=MET.base;
function M(o){return mb.add(o);}
var OFF={BENC:0x159d1c,BDEC:0x15997c,CBCE:0x159de4,CBCD:0x159f58,EINIT:0x159d60};
function hx(p,n){try{var u=new Uint8Array(p.readByteArray(n)),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}catch(e){return null;}}
var curKey=null,curIv=null,cap=[],CAPMAX=200000;
Interceptor.attach(M(OFF.EINIT),{onEnter:function(a){var kb=16;try{kb=a[2].toInt32();}catch(e){}
  try{curKey=hx(a[1],kb>0&&kb<=32?kb:16);}catch(e){}try{curIv=hx(a[3],16);}catch(e){}}});
function blk(off,name){Interceptor.attach(M(off),{
  onEnter:function(a){this.i=a[1];this.o=a[2];this.k=curKey;},
  onLeave:function(){if(cap.length<CAPMAX)cap.push({t:name,in:hx(this.i,16),out:hx(this.o,16),key:this.k});}});}
blk(OFF.BENC,'BENC');blk(OFF.BDEC,'BDEC');blk(OFF.CBCE,'CBCE');blk(OFF.CBCD,'CBCD');
rpc.exports={dump:function(){return cap;},n:function(){return cap.length;}};
send({tag:'READY',mb:mb.toString()});
'''
dev=frida.get_usb_device(timeout=5); s=dev.attach(pid)
scr=s.create_script(JS)
scr.on('message',lambda m,d: print('EV',json.dumps(m.get('payload',m)),flush=True))
scr.load()
# generate signing activity: swipes + taps
def activity():
    for _ in range(int(DUR/1.5)):
        subprocess.run([ADB,'shell','input','swipe','540','1400','540','400','120'],capture_output=True)
        time.sleep(1.2)
threading.Thread(target=activity,daemon=True).start()
time.sleep(DUR)
cap=scr.exports_sync.dump()
open('_blkcap.json','w').write(json.dumps(cap))
print('CAPTURED',len(cap),'block ops',flush=True)
s.detach()

# offline search for ground-truth store ciphertext blocks
targets={
 'msf3_5a78_blk0':'08134acf42c8f4127fd3a3e98b4b7956',
 'mss_9b8e_blk0':'75aa62270249304c2290151a22d4ca79',
 'mss_9b8e_blk1':'ed68d9bb3d8a01b839b7004dcb41051a',
 'mss_9b8e_blkLAST':'89502e13ecdf2c6d0d8f4d9d7b784eda',
 'msp_092f_blk0':'c3b27a642260175cb483156827c01af2',
}
byin={}; byout={}
for e in cap:
    byin.setdefault(e['in'],[]).append(e)
    byout.setdefault(e['out'],[]).append(e)
print('--- ground-truth block search ---',flush=True)
for name,blkhex in targets.items():
    hi=byin.get(blkhex); ho=byout.get(blkhex)
    print('%-18s as-INPUT:%s  as-OUTPUT:%s'%(name,
       ('%s key=%s -> out=%s'%(hi[0]['t'],hi[0]['key'],hi[0]['out'])) if hi else 'no',
       ('%s key=%s <- in=%s'%(ho[0]['t'],ho[0]['key'],ho[0]['in'])) if ho else 'no'),flush=True)
# key histogram
from collections import Counter
kc=Counter(e['key'] for e in cap if e['key'])
print('--- keys seen (top) ---',flush=True)
for k,n in kc.most_common(6): print('  %s x%d'%(k,n),flush=True)
tc=Counter(e['t'] for e in cap)
print('op types',dict(tc),flush=True)
