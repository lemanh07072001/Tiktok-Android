'use strict';
function libc(){ return Process.getModuleByName('libc.so'); }
function E(n){ try{const p=libc().findExportByName(n); if(p)return p;}catch(e){} try{return Module.getGlobalExportByName(n);}catch(e){} return null; }
const opendir=new NativeFunction(E('opendir'),'pointer',['pointer']);
const readdir=new NativeFunction(E('readdir'),'pointer',['pointer']);
const closedir=new NativeFunction(E('closedir'),'int',['pointer']);

const ROOT='/data/user/0/com.zhiliaoapp.musically';
let nfiles=0, nhits=0;
function isMsp(nm){ return nm.indexOf('.msp_')>=0||nm.indexOf('.msfs_')>=0||nm.indexOf('.msf3_')>=0; }
function readHead(path, n){
  try{ const f=new File(path,'rb'); const b=f.readBytes(n); f.close();
    const u=new Uint8Array(b); let h=''; for(let i=0;i<u.length;i++)h+=('0'+u[i].toString(16)).slice(-2); return h;
  }catch(e){ return 'ERR:'+e; }
}
function walk(dir, depth){
  if(depth>7) return;
  const d=opendir(Memory.allocUtf8String(dir));
  if(d.isNull()) return;
  let ent;
  while(!(ent=readdir(d)).isNull()){
    let nm; try{ nm=ent.add(19).readUtf8String(); }catch(e){ continue; }
    if(nm==='.'||nm==='..') continue;
    const dtype=ent.add(18).readU8();
    const full=dir+'/'+nm;
    if(dtype===4){ walk(full, depth+1); }
    else { nfiles++;
      if(isMsp(nm)){ nhits++;
        let sz=-1; try{ const st=new File(full,'rb'); st.seek(0,2); sz=st.tell?st.tell():-1; st.close(); }catch(e){}
        send({t:'MSP', path:full, head:readHead(full,80)});
      }
    }
  }
  closedir(d);
}
send({t:'start', root:ROOT});
walk(ROOT,0);
send({t:'done', nfiles:nfiles, nhits:nhits});
