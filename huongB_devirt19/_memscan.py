import frida, subprocess, sys, json, time
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
PKG='com.zhiliaoapp.musically'
pid=int(subprocess.check_output([ADB,'shell','pidof','-s',PKG]).strip())
print('pid',pid,flush=True)
# first-24-byte patterns
pats={
 'mss_9b8e':'75aa62270249304c2290151a22d4ca79ed68d9bb',
 'msp_092f':'c3b27a642260175cb483156827c01af211c80898',
 'msf3_5a78':'08134acf42c8f4127fd3a3e98b4b7956',
}
def sp(h): return ' '.join(h[i:i+2] for i in range(0,len(h),2))
JS='''
var PATS=%s;
function hx(p,n){try{var u=new Uint8Array(p.readByteArray(n));var s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}catch(e){return null;}}
var ranges=Process.enumerateRanges('rw-');
send({tag:'RANGES',n:ranges.length});
Object.keys(PATS).forEach(function(k){
  var pat=PATS[k],found=0;
  for(var i=0;i<ranges.length;i++){var r=ranges[i];
    try{var hits=Memory.scanSync(r.base,r.size,pat);
      for(var j=0;j<hits.length;j++){found++;
        send({tag:'HIT',store:k,addr:hits[j].address.toString(),ctx:hx(hits[j].address,64),
              region:r.base.toString()+'+'+r.size, prot:r.protection});
        if(found>=6)break;}
    }catch(e){}
    if(found>=6)break;
  }
  send({tag:'DONE',store:k,found:found});
});
send({tag:'SCANEND'});
'''%(json.dumps({k:sp(v) for k,v in pats.items()}))
dev=frida.get_usb_device(timeout=5); s=dev.attach(pid)
scr=s.create_script(JS)
def on(m,d):
    if m.get('type')=='send': print('EV',json.dumps(m['payload']),flush=True)
    else: print('ERR',m,flush=True)
scr.on('message',on); scr.load()
time.sleep(8); s.detach()
