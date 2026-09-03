'use strict';
// Combined LIGHT capture (entry/leave hooks only — safe, no VM tracing):
//   Hook A: decoder 0x891f4 (hex_to_bytes) — every 16-byte decode → token
//   Hook B: SM3 compression 0xa0748 — reconstruct #19 = SM3(query||slot16(16)||'0'),
//           slot16 = message[-17:-1]  (the PROVEN slot16 extraction, note 33 §7)
// Goal: is the SM3-#19 slot16 present in the decoder token set (same spawn)?
//   YES => 0x891f4 is ON the slot16 path.  NO => decoder is a red herring for slot16.
const SO='libmetasec_ov.so';
const DEC=0x891f4;   // x0=input std::string(len@+4, data ptr@+8); x8=sret struct(nbytes@+4, ptr@+8)
const SM3=0xa0748;   // state hx at [x0+8..+0x28]; 64B input block at x1
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function asc(u,a,b){let s='';for(let i=a;i<b;i++)s+=String.fromCharCode(u[i]);return s;}

let base=null; let decSeq=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;

  // ── Hook A: decoder 0x891f4 ─────────────────────────────────────────
  Interceptor.attach(base.add(DEC),{
    onEnter(){ const c=this.context;
      try{ this._x8=c.x8; this._x0=c.x0; this._inlen=ptr(c.x0).add(4).readU32(); }
      catch(e){ this._x8=null; } },
    onLeave(){ if(!this._x8) return;
      try{
        const outlen=ptr(this._x8).add(4).readU32(); if(outlen!==16) return;
        const dptr=ptr(this._x8).add(8).readPointer();
        const slot16=hx(dptr.readByteArray(16));
        let in_ascii=null;
        try{ const ip=ptr(this._x0).add(8).readPointer(); in_ascii=asc(new Uint8Array(ip.readByteArray(this._inlen)),0,this._inlen); }catch(e){}
        send({t:'DEC',seq:decSeq++,tid:this.threadId,ts:Date.now(),in_ascii:in_ascii,slot16:slot16});
      }catch(e){} }
  });

  // ── Hook B: SM3 → reconstruct #19 → slot16 = msg[-17:-1] ────────────
  const chain={};
  Interceptor.attach(base.add(SM3),{
    onEnter(){ const c=this.context; let st,inp;
      try{ st=hx(c.x0.add(8).readByteArray(32)); inp=new Uint8Array(c.x1.readByteArray(64)); }catch(e){ return; }
      const tid=this.threadId;
      if(st===IV_LE) chain[tid]=Array.from(inp);
      else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); }
      else return;
      const a=chain[tid], L=a.length; if(L<9) return;
      let bitlen=0; for(let i=L-8;i<L;i++) bitlen=bitlen*256+a[i]; const mlen=bitlen/8;
      if(!(mlen>16 && mlen<L) || a[mlen]!==0x80) return;         // not a finished msg yet
      if(a[mlen-1]!==0x30 || mlen<200){ delete chain[tid]; return; }
      const full=asc(a,0,mlen);
      if(full.indexOf('device_platform=')<0){ delete chain[tid]; return; }
      let slot=''; for(let i=mlen-17;i<mlen-1;i++) slot+=('0'+a[i].toString(16)).slice(-2);
      send({t:'S16',tid:tid,ts:Date.now(),slot16:slot,mlen:mlen,qhead:full.slice(0,72)});
      delete chain[tid];
    }
  });

  send({t:'info',msg:'combined installed base='+base});
  return true;
}
setInterval(()=>send({t:'mon',ds:decSeq}), 5000);
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{
  onEnter(a){ try{ this.p=a[0].readCString(); }catch(e){} },
  onLeave(){ if(this.p&&this.p.indexOf(SO)>=0) install(); }
});
