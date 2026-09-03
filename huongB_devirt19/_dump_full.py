import sys, os, json, frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PID = int(sys.argv[1])
JS = r'''
'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
if(!m){ send({t:'err',msg:'module not found'}); }
else {
  send({t:'info', base:m.base.toString(), size:m.size, path:m.path});
  const PG=0x1000; let off=0; let okc=0, badc=0;
  while(off<m.size){
    const n=Math.min(PG, m.size-off);
    let b=null; try{ b=m.base.add(off).readByteArray(n); }catch(e){}
    if(b){ okc++; send({t:'pg', off:off}, b); } else { badc++; send({t:'gap', off:off, n:n}); }
    off+=n;
  }
  send({t:'done', ok:okc, bad:badc});
}
'''
base=[None]; size=[0]; path=[None]; pages={}; gaps=[]
def on_msg(m,d):
    p=m.get('payload') or {}
    t=p.get('t')
    if t=='info': base[0]=p['base']; size[0]=p['size']; path[0]=p['path']; print('[base]',p['base'],'size',hex(p['size']),flush=True)
    elif t=='pg':
        if d: pages[p['off']]=d
    elif t=='gap': gaps.append((p['off'],p['n']))
    elif t=='done': print('[done] ok=%d bad=%d'%(p['ok'],p['bad']),flush=True)
    elif t=='err': print('[ERR]',p['msg'],flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(PID); sc=sess.create_script(JS); sc.on('message',on_msg); sc.load()
import time; time.sleep(8)
try: sess.detach()
except: pass
if size[0]==0:
    print('[FAIL] no module/size'); sys.exit(1)
# assemble a complete-offset image; gaps -> zero fill (kept for alignment)
buf=bytearray(size[0])
tot=0
for off,d in pages.items():
    buf[off:off+len(d)]=d; tot+=len(d)
open('_code_dump_full.bin','wb').write(buf)
json.dump({'base':base[0],'size':size[0],'path':path[0],'gaps':gaps,'ok_bytes':tot}, open('_code_dump_full_meta.json','w'))
print('[SAVED] _code_dump_full.bin size=%d ok_bytes=%d gaps=%d'%(len(buf),tot,len(gaps)),flush=True)
# report gap coverage in the data-tail region of interest
tail=[g for g in gaps if g[0]>=0x1c0000]
print('[tail-gaps >=0x1c0000] %d  first: %s'%(len(tail), ['0x%x'%g[0] for g in tail[:8]]))
for probe in (0x1d9488,0x1e0530,0x1e0560,0x1dffe0,0x1efbd8):
    ok = all(not(g[0]<=probe<g[0]+g[1]) for g in gaps) and probe<size[0]
    print('  probe 0x%06x -> %s'%(probe, 'CAPTURED' if ok else 'gap/missing'))
