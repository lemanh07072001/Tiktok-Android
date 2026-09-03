// _vm_singleshot.js — capture ONE complete VM entry state at 0x55950 then DETACH (survivable).
// Reads registers + regfile + the memory reachable via every regfile pointer + stack, so unicorn
// can replay the (self-contained, per Agent C) slot16 computation offline. Single hit → detach.
'use strict';
const SO = 'libmetasec_ov.so';
const VM_ENTRY = 0x52924;    // capture at FUNCTION ENTRY (fresh frame, no frida-polluted loop-head stack) of slot16-invocation
const SM3 = 0xa0748;
const IV_LE = '6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rd(p,n){ try{ return hx(ptr(p).readByteArray(n)); }catch(e){ return null; } }

function install(){
  const m = Process.findModuleByName(SO); if(!m) return false;
  const base = m.base; const loEnd = base; const hiEnd = base.add(0x200000);
  let vmL = null, captured = false, fhits = 0;
  const chain = {};
  let lastCtxPtr = null, capturedTid = 0, sentCtx = false;
  // capture the singleton-getter's returned CONTEXT pointer ([x20+0x10] at getter tail 0x13b04c).
  // For the captured F invocation we want the ctxptr from F's OWN getter (same tid, AFTER F-entry).
  Interceptor.attach(base.add(0x13b04c), { onEnter(){
    try{ lastCtxPtr = this.context.x20.add(0x10).readPointer().toString(); }catch(e){}
    if (capturedTid && this.threadId===capturedTid && !sentCtx){ sentCtx=true; send({ t:'fctxptr', val:lastCtxPtr }); }
  }});

  const F_PROG = parseInt((typeof MSPROG!=='undefined'&&MSPROG)||'0x18f430');  // seed-gen (called BY producer) — capture stack to walk fp-chain offline -> producer
  const SKIP_N = parseInt((typeof MSSKIP!=='undefined'&&MSSKIP)||'1');
  let entryX24 = null, sentOut = false;   // onLeave of VM-entry captures output regfile (light, once/invocation)
  vmL = Interceptor.attach(base.add(VM_ENTRY), {
    onEnter(){
      if (captured) return;
      if (!this.context.x0.equals(base.add(F_PROG))) return;   // ONLY F's invocation (x0 = program 0x191f40)
      fhits++;
      if (fhits < SKIP_N) { send({ t:'info', msg:'F hit #'+fhits+' (waiting for #'+SKIP_N+', singleton populated)'}); return; }
      send({ t:'info', msg:'F invocation #'+fhits+' ENTRY (x0=0x191f40) tid='+this.threadId+' — capturing...' });
      captured = true; capturedTid = this.threadId;   // F's OWN getter (same tid, after entry) gives the matching ctxptr
      try {
      const c = this.context;
      const regs = {};
      ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15',
       'x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','fp','lr','sp','pc'].forEach(r=>{
        try{ regs[r]=c[r].toString(); }catch(e){ regs[r]='?'; }
      });
      // CONSISTENT ephemeral capture (frozen thread): light BFS of regfile/register pointer targets.
      // Efficient byte-scan (no hex-string), hard-capped -> fast, no hang. Stable regions come from enricher.
      const mem = {};
      const regfile = rd(c.x24, 256);
      entryX24 = c.x24; this.doCapture = true;   // mark for onLeave output-regfile capture
      const seenpg = {};
      const PGMASK = ptr('0xfffffffffffff000');
      function looksPtr2(lo, hi){ return (hi === 0x78 || hi === 0x79 || hi === 0x7a || hi === 0x7b || hi === 0x7c || hi === 0x7d); }
      function grabPage(pv){
        try{
          const pg = ptr(pv).and(PGMASK);
          const key = pg.toString();
          if (seenpg[key]) return null;
          seenpg[key] = 1;
          const ab = pg.readByteArray(0x1000);
          mem[key] = hx(ab);
          return new Uint8Array(ab);
        }catch(e){ return null; }
      }
      function hb(x){ return ('0'+x.toString(16)).slice(-2); }
      function scanPtrs(u8, out){
        // pointers are 40-bit (0x78xxxxxxxx): byte[4]=0x78-0x7d, byte[5..7]=0. Build full 5-byte ptr; grabPage masks.
        for (let o=0; o<u8.length; o+=8){
          const b4=u8[o+4];
          if (b4>=0x78 && b4<=0x7d && u8[o+5]===0 && u8[o+6]===0 && u8[o+7]===0){
            out.push(ptr('0x'+b4.toString(16)+hb(u8[o+3])+hb(u8[o+2])+hb(u8[o+1])+hb(u8[o])));
          }
        }
      }
      // explicit contiguous .data region (runtime-init tables + singleton ptrs) — read FIRST, seed BFS from it.
      // base+0x1d8000..0x1f4000 (r-- 0x1d8000-0x1f0000 + rw 0x1f0000-0x1f4000, contiguous, no gap).
      // Covers table1 0x1d9488, table2 0x1d9688, singleton ptr 0x1efbd8, dispatch ptr slots 0x1f00e0/0x1f00e8.
      const soData = rd(base.add(0x1d8000), 0x1c000);
      let frontier = [];
      ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x19','x20','x21','x25','x26','fp','lr','sp'].forEach(r=>{ try{ frontier.push(c[r]); }catch(e){} });
      try{ for (let i=0;i<32;i++) frontier.push(c.x24.add(i*8).readU64()); }catch(e){}
      // seed frontier with runtime singleton/table pointer targets so their objects get captured
      [0x1efbd8,0x1f00e0,0x1f00e8].forEach(off=>{ try{ frontier.push(base.add(off).readPointer()); }catch(e){} });
      if (lastCtxPtr) { try{ frontier.push(ptr(lastCtxPtr)); }catch(e){} }   // capture the device-stable context object graph
      if (soData){ // scan the data region for pointers -> capture the singleton object graph
        const u8=new Uint8Array(soData.match(/../g).map(h=>parseInt(h,16)));
        scanPtrs(u8, frontier);
      }
      const CAP=1600;
      for (let lvl=0; lvl<6 && Object.keys(seenpg).length < CAP; lvl++){
        const next = [];
        for (let k=0;k<frontier.length && Object.keys(seenpg).length<CAP;k++){
          const u8 = grabPage(frontier[k]);
          if (u8) scanPtrs(u8, next);
        }
        frontier = next;
      }
      const soRW = null;
      // maps (for replay gum-cleanup) via enumerateRanges
      let mapsStr='';
      try{ Process.enumerateRanges('r--').forEach(r=>{ mapsStr += r.base.toString().slice(2)+'-'+r.base.add(r.size).toString().slice(2)+' '+r.protection+'p 0 0 0 '+(r.file?r.file.path:'')+'\n'; }); }catch(e){}
      try{ Process.enumerateRanges('r-x').forEach(r=>{ mapsStr += r.base.toString().slice(2)+'-'+r.base.add(r.size).toString().slice(2)+' '+r.protection+'p 0 0 0 '+(r.file?r.file.path:'')+'\n'; }); }catch(e){}
      let bcFull = rd(base.add(0x17b000), 0x1b000);   // r-x contiguous → 1 read
      let bc=null, bcptr=null;
      try{ bcptr = c.x23.readPointer(); bc = rd(bcptr, 2048); }catch(e){}
      // stack: fixed start = sp-0x800, size 0x4000 (covers sp-0x800 .. sp+0x3800). vaddr MUST match start.
      const stackStart = c.sp.sub(0x800);
      let stack = rd(stackStart, 0x4000);
      if (!stack) stack = rd(stackStart, 0x2000);      // shrink if it spans a guard

      // send big regions as SEPARATE messages (avoid one oversized payload dropping fields)
      send({ t:'region', name:'bcFull', vaddr: base.add(0x17b000).toString(), hex: bcFull });
      send({ t:'region', name:'soData', vaddr: base.add(0x1d8000).toString(), hex: soData });
      send({ t:'maps', maps: mapsStr });
      send({ t:'region', name:'soRW',   vaddr: base.add(0x1eb000).toString(), hex: soRW });
      send({ t:'region', name:'stack',  vaddr: stackStart.toString(),         hex: stack });
      send({ t:'region', name:'regfile',vaddr: c.x24.toString(),              hex: regfile });
      if (bc) send({ t:'region', name:'bytecode', vaddr: bcptr.toString(),    hex: bc });
      // send windows in chunks of 60 to keep each message small
      const keys = Object.keys(mem);
      for (let s=0; s<keys.length; s+=60){
        const chunk = {};
        for (let j=s; j<Math.min(s+60,keys.length); j++) chunk[keys[j]] = mem[keys[j]];
        send({ t:'memchunk', mem: chunk });
      }
      send({ t:'entry', base: base.toString(), tid: this.threadId, nmem: keys.length,
             regs: regs, bcptr: bcptr?bcptr.toString():null, ctxptr: lastCtxPtr });
      // keep vmL attached until onLeave captures the output regfile (this invocation returns)
      send({ t:'info', msg:'VM entry captured (tid '+this.threadId+') — waiting onLeave for output' });
      } catch(err){ send({ t:'info', msg:'VM onEnter ERROR: '+err+' @ '+(err.stack||'') }); try{vmL.detach();}catch(e){} }
    },
    onLeave(){
      if (!this.doCapture || sentOut) return;
      sentOut = true;
      try { send({ t:'outrf', hex: rd(entryX24, 256), x24: entryX24 ? entryX24.toString() : null }); }
      catch(e){ send({ t:'info', msg:'outrf ERR '+e }); }
      try{ vmL.detach(); }catch(e){}
      send({ t:'info', msg:'output regfile captured + DETACHED' });
    }
  });

  // SM3: keep capturing slot16 (for offline validation / matching)
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
      const full=''; let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
      if (f.indexOf('device_platform=')<0||f.indexOf('&device_id=')<0){ delete chain[tid]; return; }
      let slot=''; for(let i=mlen-17;i<mlen-1;i++) slot+=('0'+a[i].toString(16)).slice(-2);
      send({ t:'slot', tid:tid, slot16:slot, query:f.slice(0,mlen-17) });
      delete chain[tid];
    }
  });

  send({ t:'info', msg:'singleshot installed base='+base });
  return true;
}
if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a){ try{ this.p=a[0].readCString(); }catch(e){} },
  onLeave(){ if(this.p&&this.p.indexOf(SO)>=0) install(); }
});
