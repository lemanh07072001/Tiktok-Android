// _slot16_bufcorr.js v2 — BURST-then-DETACH (anti-crash).
// The VM hook (0x55950, ~772x/sign) is HEAVY, so it runs only until the FIRST nonzero slot16 is
// captured, then DETACHES itself — one short burst, not continuous. Goal (path B): grab the
// regfile[29] ratchet-buffer window correlated with a nonzero slot16, to test offline whether
// slot16 is a window of that buffer (→ unicorn-replayable) and whether the buffer is reusable.
'use strict';
const SO = 'libmetasec_ov.so';
const SM3 = 0xa0748;
const VM  = 0x55950;
const IV_LE = '6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
const WIN_BACK = 64;
const WIN_FWD  = 448;     // total 512B window around *regfile[29]
const KEEP = 8;           // rolling last-N distinct buffers per thread
const HARD_CAP = 4000;    // safety: detach after this many VM entries even w/o nonzero

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function asc(u,a,b){let s='';for(let i=a;i<b;i++)s+=String.fromCharCode(u[i]);return s;}

function install(){
  const m = Process.findModuleByName(SO); if(!m) return false;
  const base = m.base;
  const chain = {};
  const bufs  = {};
  let vmListener = null;
  let vmCount = 0;
  let done = false;

  function stopVM(){
    if (vmListener){ try{ vmListener.detach(); }catch(e){} vmListener = null;
      send({ t:'info', msg:'VM hook DETACHED after '+vmCount+' entries' }); }
  }

  vmListener = Interceptor.attach(base.add(VM), {
    onEnter(){
      if (done) return;
      vmCount++;
      if (vmCount > HARD_CAP){ done = true; stopVM(); return; }
      const tid = this.threadId;
      try {
        const r29 = this.context.x24.add(29*8).readU64();
        if (r29.compare(0)===0) return;
        const win = ptr(r29).sub(WIN_BACK).readByteArray(WIN_BACK + WIN_FWD);
        const h = hx(win);
        let arr = bufs[tid] || (bufs[tid]=[]);
        if (arr.length && arr[arr.length-1].win === h) return;
        arr.push({ r29: r29.toString(16), win: h });
        if (arr.length > KEEP) arr.shift();
      } catch(e){}
    }
  });

  Interceptor.attach(base.add(SM3), {
    onEnter(){
      const tid = this.threadId; let st, inp;
      try { st = hx(this.context.x0.add(8).readByteArray(32)); inp = new Uint8Array(this.context.x1.readByteArray(64)); }
      catch(e){ return; }
      if (st === IV_LE) chain[tid] = Array.from(inp);
      else if (chain[tid]) { for(let i=0;i<64;i++) chain[tid].push(inp[i]); }
      else return;
      const a = chain[tid], L = a.length;
      if (L < 9) return;
      let bitlen = 0; for(let i=L-8;i<L;i++) bitlen = bitlen*256 + a[i];
      const mlen = bitlen/8;
      if (!(mlen>16 && mlen<L) || a[mlen]!==0x80) return;
      if (a[mlen-1]!==0x30 || mlen<200){ delete chain[tid]; return; }
      const full = asc(a,0,mlen);
      if (full.indexOf('device_platform=')<0 || full.indexOf('&device_id=')<0){ delete chain[tid]; return; }
      let slot=''; for(let i=mlen-17;i<mlen-1;i++) slot += ('0'+a[i].toString(16)).slice(-2);
      const isZero = (slot === '00'.repeat(16));
      send({ t:'obs', ts_wall: Date.now(), slot16: slot, query: full.slice(0, mlen-17),
             zero: isZero, bufs: (isZero ? [] : (bufs[tid]||[])), vmCount: vmCount });
      delete chain[tid];
      bufs[tid] = [];
      if (!isZero && !done){ done = true; stopVM(); }   // got a nonzero + its bufs → stop heavy hook
    }
  });

  send({ t:'info', msg:'bufcorr-v2 installed base='+base+' (burst-then-detach)' });
  return true;
}

if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a){ try{ this.p=a[0].readCString(); }catch(e){} },
  onLeave(){ if(this.p && this.p.indexOf(SO)>=0) install(); }
});
