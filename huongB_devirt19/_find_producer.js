// _find_producer.js — directly identify which VM-call produces slot16.
// Hook the 3 candidate RETURN sites (right after BL 0x52924, frame still live) + #19 SM3.
// At each return: dump the stack output-buffer window [sp-0x10 .. sp+0x60] keyed by tid.
// At #19 nonzero slot16: report which candidate's dumped window CONTAINS the 16 slot16 bytes.
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
// return sites (LR values) = instr AFTER the BL 0x52924
const RETS = { '0x9fd74':'A', '0x1384e8':'B', '0x10ac84':'C' };
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; const chain={}; const bufs={};   // tid -> {A:hex,B:hex,C:hex} (latest dump per candidate)
  function deepDump(sp){
    // dump sp-window + dereference every 40-bit pointer in it, dumping 64B at each target.
    let win=null; const deep=[];
    try{ win=hx(sp.sub(0x10).readByteArray(0x90)); }catch(e){}
    if(win){ const u=new Uint8Array(win.match(/../g).map(h=>parseInt(h,16)));
      for(let o=0;o<u.length-8;o+=8){
        if(u[o+4]>=0x78&&u[o+4]<=0x7d&&u[o+5]===0&&u[o+6]===0&&u[o+7]===0){
          const hb=x=>('0'+x.toString(16)).slice(-2);
          try{ const p=ptr('0x'+u[o+4].toString(16)+hb(u[o+3])+hb(u[o+2])+hb(u[o+1])+hb(u[o]));
               deep.push(hx(p.readByteArray(64))); }catch(e){}
        }
      }
    }
    return {win:win, deep:deep};
  }
  Object.keys(RETS).forEach(off=>{
    const label=RETS[off];
    Interceptor.attach(base.add(parseInt(off,16)),{onEnter(){
      const tid=this.threadId;
      (bufs[tid]=bufs[tid]||{})[label]=deepDump(this.context.sp);
    }});
  });
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
    if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; }
    let slot=''; for(let i=mlen-17;i<mlen-1;i++) slot+=('0'+a[i].toString(16)).slice(-2);
    {
      const isZero = (slot==='00'.repeat(16));
      // check which candidate's dumped window contains these 16 bytes (raw / xor0xed / reversed)
      const b=bufs[tid]||{}; const found={};
      const raw=slot, rev=slot.match(/../g).reverse().join(''),
            xored=slot.match(/../g).map(h=>('0'+((parseInt(h,16))^0xed).toString(16)).slice(-2)).join('');
      function search(hexstr){ if(!hexstr) return -1;
        if(hexstr.indexOf(raw)>=0) return 'RAW@'+(hexstr.indexOf(raw)/2);
        if(hexstr.indexOf(rev)>=0) return 'REV@'+(hexstr.indexOf(rev)/2);
        if(hexstr.indexOf(xored)>=0) return 'XOR@'+(hexstr.indexOf(xored)/2);
        return -1; }
      Object.keys(RETS).forEach(off=>{ const lbl=RETS[off]; const bb=b[lbl]; if(!bb) return;
        let r=search(bb.win); if(r!==-1){ found[lbl]='win:'+r; return; }
        for(let i=0;i<(bb.deep||[]).length;i++){ r=search(bb.deep[i]); if(r!==-1){ found[lbl]='deep['+i+']:'+r; return; } }
      });
      send({t:'sm3',tid:tid,slot16:slot,zero:isZero,found:found,query:f.slice(0,mlen-17),haveBufs:Object.keys(b)});
    }
    delete chain[tid];
  }});
  send({t:'info',msg:'find-producer installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
