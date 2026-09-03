import sys,os,json,frida
os.chdir(os.path.dirname(os.path.abspath(__file__)))
PID=int(sys.argv[1])
JS=r'''
'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
if(!m){ send({t:'err',msg:'module not found'}); }
else {
  send({t:'info', base:m.base.toString(), size:m.size, path:m.path});
  // enumerate ranges of the module, dump r-x (code) ranges
  const ranges=Process.enumerateRanges('r-x').filter(r=>{ try{ return r.base.compare(m.base)>=0 && r.base.compare(m.base.add(m.size))<0; }catch(e){ return false; } });
  send({t:'ranges', n:ranges.length, list:ranges.map(r=>({base:r.base.toString(),size:r.size,prot:r.protection}))});
  // dump the whole module image [base, base+size) in chunks (decrypted live)
  const CH=0x40000; let off=0;
  while(off<m.size){
    const n=Math.min(CH, m.size-off);
    let b=null; try{ b=m.base.add(off).readByteArray(n); }catch(e){}
    send({t:'chunk', off:off, ok:!!b}, b);
    off+=n;
  }
  send({t:'done'});
}
'''
base=[None]; size=[0]; path=[None]; chunks={}
f=open('_code_dump.bin','wb')
def on_msg(m,d):
    p=m.get('payload') or {}
    t=p.get('t')
    if t=='info': base[0]=p['base']; size[0]=p['size']; path[0]=p['path']; print('[base]',p['base'],'size',hex(p['size']),p['path'],flush=True)
    elif t=='ranges': print('[ranges]',p['n'],p['list'][:6],flush=True)
    elif t=='chunk':
        if d: chunks[p['off']]=d
    elif t=='done': print('[done-script]',flush=True)
    elif t=='err': print('[ERR]',p['msg'],flush=True)
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sess=dev.attach(PID); sc=sess.create_script(JS); sc.on('message',on_msg); sc.load()
import time; time.sleep(6)
try: sess.detach()
except: pass
# assemble
tot=0
for off in sorted(chunks): f.write(chunks[off]); tot+=len(chunks[off])
f.close()
json.dump({'base':base[0],'size':size[0],'path':path[0]}, open('_code_dump_meta.json','w'))
print('[SAVED] _code_dump.bin bytes=%d base=%s size=%s'%(tot,base[0],hex(size[0]) if size[0] else '?'),flush=True)
