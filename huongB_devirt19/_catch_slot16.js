// _catch_slot16.js — minimal SM3-tail observer. Reconstructs the SM3 message stream,
// extracts the 16B slot16 (the 16 bytes before the trailing 0x30 terminator), reports each nonzero one.
// Purpose: re-establish ground-truth on the AVD (confirm we can catch a nonzero slot16 during register).
'use strict';
const SO = 'libmetasec_ov.so', SM3 = 0xa0748;
const IV_LE = '6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
const chain = {};           // per-thread accumulated SM3 message bytes
let seen = 0, nz = 0;

function hxab(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }

function install(){
  const m = Process.findModuleByName(SO);
  if(!m){ return false; }
  const base = m.base;
  Interceptor.attach(base.add(SM3), { onEnter(){
    const tid=this.threadId; let st, inp;
    try { st = hxab(this.context.x0.add(8).readByteArray(32)); inp = new Uint8Array(this.context.x1.readByteArray(64)); }
    catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp);           // fresh SM3 state -> first block
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); }  // continuation block
    else return;
    const a=chain[tid], L=a.length; if(L<9) return;
    // last 8 bytes = bit-length (big-endian); mlen = message byte length
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16 && mlen<L) || a[mlen]!==0x80) return;    // 0x80 padding must follow message
    if(a[mlen-1]!==0x30 || mlen<200){ delete chain[tid]; return; }  // must end with 0x30 terminator
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
    if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; } // must be a sign body
    // slot16 = 16 bytes at [mlen-17 .. mlen-1)
    let slot='', pr=0; for(let i=mlen-17;i<mlen-1;i++){ slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e) pr++; }
    delete chain[tid];
    seen++;
    const isNonzero = (slot!=='00'.repeat(16)) && pr<12;
    if(isNonzero){ nz++;
      // small context: the query prefix (first 80 chars) helps identify which endpoint
      const qh = f.indexOf('?')>=0 ? f.slice(f.indexOf('?')+1, f.indexOf('?')+81) : f.slice(0,80);
      send({t:'slot16', n:nz, tid:tid, slot:slot, mlen:mlen, qpre:qh});
    } else if(seen%20===0){
      send({t:'stat', seen:seen, nz:nz});
    }
  }});
  send({t:'info', msg:'catch-slot16 installed base='+base+' sm3=0x'+SM3.toString(16)});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  { onEnter(a){ try{ this.p=a[0].readCString(); }catch(e){} },
    onLeave(){ if(this.p && this.p.indexOf(SO)>=0) install(); } });
