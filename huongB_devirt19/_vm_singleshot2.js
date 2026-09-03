// _vm_singleshot2.js — HARDENED capture for route A.
// Key change vs v1: the heavy pointer-BFS runs at F's onLeave (AFTER the 2 device-data
// call-outs 0x13b010/0x13b034 have populated the singleton context [x20+0x10]), so the
// device object-graph that F's loads chase through is actually in the image.
// Also: reads F's REAL output slot16 directly from *(entryX4+8) at onLeave (self-consistent
// oracle, no SM3 text-tail false positives), and counts call-out hits during the captured F.
'use strict';
const SO = 'libmetasec_ov.so';
const VM_ENTRY = 0x52924;
const SM3 = 0xa0748;
const IV_LE = '6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rd(p,n){ try{ return hx(ptr(p).readByteArray(n)); }catch(e){ return null; } }
function hb(x){ return ('0'+x.toString(16)).slice(-2); }

function install(){
  const m = Process.findModuleByName(SO); if(!m) return false;
  const base = m.base;
  let captured = false, fhits = 0;
  const chain = {};
  let lastCtxPtr = null, capturedTid = 0, sentCtx = false;
  let capturing = false, callouts = {a:0,b:0};

  // singleton-getter tail: [x20+0x10] is the device-data object pointer (populated by call-outs).
  Interceptor.attach(base.add(0x13b04c), { onEnter(){
    try{ lastCtxPtr = this.context.x20.add(0x10).readPointer().toString(); }catch(e){}
    if (capturedTid && this.threadId===capturedTid && !sentCtx){ sentCtx=true; send({ t:'fctxptr', val:lastCtxPtr }); }
  }});
  // count the 2 device-data call-outs that fire DURING the captured F (confirms it's a real signing).
  Interceptor.attach(base.add(0x13b010), { onEnter(){ if(capturing && this.threadId===capturedTid) callouts.a++; }});
  Interceptor.attach(base.add(0x13b034), { onEnter(){ if(capturing && this.threadId===capturedTid) callouts.b++; }});

  const F_PROG = parseInt((typeof MSPROG!=='undefined'&&MSPROG)||'0x191f40');
  const SKIP_N = parseInt((typeof MSSKIP!=='undefined'&&MSSKIP)||'1');
  let entryX24 = null, entryX4 = null, entryRoots = [], vmL = null;

  vmL = Interceptor.attach(base.add(VM_ENTRY), {
    onEnter(){
      if (captured) return;
      if (!this.context.x0.equals(base.add(F_PROG))) return;
      fhits++;
      if (fhits < SKIP_N) { send({ t:'info', msg:'F hit #'+fhits+' (waiting for #'+SKIP_N+')'}); return; }
      send({ t:'info', msg:'F invocation #'+fhits+' ENTRY (x0='+base.add(F_PROG)+') tid='+this.threadId+' — entry snapshot...' });
      captured = true; capturedTid = this.threadId; capturing = true; this.doCapture = true;
      try {
      const c = this.context;
      const regs = {};
      ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15',
       'x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','fp','lr','sp','pc'].forEach(r=>{
        try{ regs[r]=c[r].toString(); }catch(e){ regs[r]='?'; }
      });
      entryX24 = c.x24; entryX4 = c.x4;
      // ENTRY-state static/immutable regions (input objects are stable entry->exit).
      const regfile = rd(c.x24, 256);
      const soData = rd(base.add(0x1d8000), 0x1c000);
      const bcFull = rd(base.add(0x17b000), 0x1b000);
      let bc=null, bcptr=null;
      try{ bcptr = c.x23.readPointer(); bc = rd(bcptr, 2048); }catch(e){}
      const stackStart = c.sp.sub(0x800);
      let stack = rd(stackStart, 0x4000); if (!stack) stack = rd(stackStart, 0x2000);
      // save ENTRY pointer roots (input/q2 object graph) for the onLeave BFS.
      entryRoots = [];
      ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x19','x20','x21','x25','x26','fp','lr','sp'].forEach(r=>{ try{ entryRoots.push(c[r]); }catch(e){} });
      try{ for (let i=0;i<32;i++) entryRoots.push(c.x24.add(i*8).readU64()); }catch(e){}
      // stash for onLeave
      this.regs = regs; this.regfile = regfile; this.soData = soData; this.bcFull = bcFull;
      this.bc = bc; this.bcptr = bcptr; this.stack = stack; this.stackStart = stackStart;
      send({ t:'info', msg:'entry snapshot done — deferring BFS to onLeave (post call-outs)' });
      } catch(err){ send({ t:'info', msg:'onEnter ERROR: '+err }); try{vmL.detach();}catch(e){} }
    },
    onLeave(){
      if (!this.doCapture) return; this.doCapture = false; capturing = false;
      try {
      const c = this.context;
      const seenpg = {};
      const PGMASK = ptr('0xfffffffffffff000');
      const mem = {};
      function grabPage(pv){
        try{
          const pg = ptr(pv).and(PGMASK); const key = pg.toString();
          if (seenpg[key]) return null; seenpg[key] = 1;
          const ab = pg.readByteArray(0x1000); mem[key] = hx(ab); return new Uint8Array(ab);
        }catch(e){ return null; }
      }
      function scanPtrs(u8, out){
        for (let o=0; o<u8.length; o+=8){
          const b4=u8[o+4];
          if (b4>=0x78 && b4<=0x7d && u8[o+5]===0 && u8[o+6]===0 && u8[o+7]===0){
            out.push(ptr('0x'+b4.toString(16)+hb(u8[o+3])+hb(u8[o+2])+hb(u8[o+1])+hb(u8[o])));
          }
        }
      }
      // frontier = ENTRY input roots + CURRENT stable callee-saved regs + device ctxptr + singleton ptrs + soData scan
      let frontier = entryRoots.slice();
      ['x19','x20','x21','x22','x23','x24'].forEach(r=>{ try{ frontier.push(c[r]); }catch(e){} });
      [0x1efbd8,0x1f00e0,0x1f00e8].forEach(off=>{ try{ frontier.push(base.add(off).readPointer()); }catch(e){} });
      if (lastCtxPtr) { try{ frontier.push(ptr(lastCtxPtr)); frontier.push(ptr(lastCtxPtr).readPointer()); }catch(e){} }
      if (this.soData){ const u8=new Uint8Array(this.soData.match(/../g).map(h=>parseInt(h,16))); scanPtrs(u8, frontier); }
      const CAP=1800;
      for (let lvl=0; lvl<7 && Object.keys(seenpg).length < CAP; lvl++){
        const next = [];
        for (let k=0;k<frontier.length && Object.keys(seenpg).length<CAP;k++){
          const u8 = grabPage(frontier[k]); if (u8) scanPtrs(u8, next);
        }
        frontier = next;
      }
      // maps
      let mapsStr='';
      try{ Process.enumerateRanges('r--').forEach(r=>{ mapsStr += r.base.toString().slice(2)+'-'+r.base.add(r.size).toString().slice(2)+' '+r.protection+'p 0 0 0 '+(r.file?r.file.path:'')+'\n'; }); }catch(e){}
      try{ Process.enumerateRanges('r-x').forEach(r=>{ mapsStr += r.base.toString().slice(2)+'-'+r.base.add(r.size).toString().slice(2)+' '+r.protection+'p 0 0 0 '+(r.file?r.file.path:'')+'\n'; }); }catch(e){}
      // F's REAL output slot16: *(entryX4+8) -> data_ptr -> 16 bytes (same as compute_slot16.slot16()).
      let directSlot=null, dptr=null;
      try{ dptr = entryX4.add(8).readPointer(); directSlot = rd(dptr, 16); }catch(e){}
      // send everything
      send({ t:'region', name:'bcFull', vaddr: base.add(0x17b000).toString(), hex: this.bcFull });
      send({ t:'region', name:'soData', vaddr: base.add(0x1d8000).toString(), hex: this.soData });
      send({ t:'maps', maps: mapsStr });
      send({ t:'region', name:'stack',  vaddr: this.stackStart.toString(), hex: this.stack });
      send({ t:'region', name:'regfile',vaddr: entryX24.toString(),        hex: this.regfile });
      if (this.bc) send({ t:'region', name:'bytecode', vaddr: this.bcptr.toString(), hex: this.bc });
      const keys = Object.keys(mem);
      for (let s=0; s<keys.length; s+=60){
        const chunk = {}; for (let j=s; j<Math.min(s+60,keys.length); j++) chunk[keys[j]] = mem[keys[j]];
        send({ t:'memchunk', mem: chunk });
      }
      send({ t:'outrf', hex: rd(entryX24, 256), x24: entryX24.toString() });
      send({ t:'directslot', slot16: directSlot, dptr: dptr?dptr.toString():null,
             callouts_a: callouts.a, callouts_b: callouts.b });
      send({ t:'entry', base: base.toString(), tid: this.threadId, nmem: keys.length,
             regs: this.regs, bcptr: this.bcptr?this.bcptr.toString():null, ctxptr: lastCtxPtr });
      send({ t:'info', msg:'onLeave BFS done: pages='+keys.length+' callouts a='+callouts.a+' b='+callouts.b+' directSlot='+directSlot });
      try{ vmL.detach(); }catch(e){}
      } catch(err){ send({ t:'info', msg:'onLeave ERROR: '+err+' '+(err.stack||'') }); try{vmL.detach();}catch(e){} }
    }
  });

  // SM3 secondary oracle (kept, but no longer the primary; text-tails filtered by binary check downstream)
  Interceptor.attach(base.add(SM3), {
    onEnter(){
      const tid=this.threadId; let st,inp;
      try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
      if (st===IV_LE) chain[tid]=Array.from(inp);
      else if (chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); }
      else return;
      const a=chain[tid], L=a.length; if (L<9) return;
      let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
      if (!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
      if (a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
      let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
      if (f.indexOf('device_platform=')<0||f.indexOf('&device_id=')<0){ delete chain[tid]; return; }
      let slot=''; for(let i=mlen-17;i<mlen-1;i++) slot+=('0'+a[i].toString(16)).slice(-2);
      send({ t:'slot', tid:tid, slot16:slot });
      delete chain[tid];
    }
  });

  send({ t:'info', msg:'singleshot2 installed base='+base+' F_PROG='+base.add(F_PROG) });
  return true;
}
if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a){ try{ this.p=a[0].readCString(); }catch(e){} },
  onLeave(){ if(this.p&&this.p.indexOf(SO)>=0) install(); }
});
