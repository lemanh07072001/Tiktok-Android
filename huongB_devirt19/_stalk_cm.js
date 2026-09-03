// _stalk_cm.js v7 — CModule Stalker store-tracer. All mutable state in JS Memory.alloc (RW), addresses
// baked into the CModule source as literals (compiled after alloc) => CModule never writes its own globals
// (this frida build maps CModule data read-only).
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
const CAP=8192, PCAP=16384;
const ringMem=Memory.alloc(CAP*32);
const poolMem=Memory.alloc(PCAP*24);
const stateMem=Memory.alloc(16); stateMem.writeU32(0); stateMem.add(4).writeU32(0);
const R=ringMem.toString(), P=poolMem.toString(), S=stateMem.toString(), S4=stateMem.add(4).toString();
const cm = new CModule(`
#include <gum/gumstalker.h>
#include <stdint.h>
typedef struct { uint64_t pc, tgt, vlo, vhi; } Rec;
typedef struct { uint64_t pc; int32_t off; uint8_t rn, rt, rt2, pair; } SInfo;
#define RING ((Rec*)${R}ULL)
#define POOL ((SInfo*)${P}ULL)
#define RC (*(volatile uint32_t*)${S}ULL)
#define PN (*(volatile uint32_t*)${S4}ULL)
#define ALO 0x7e0000000000ULL
#define AHI 0x7f0000000000ULL
#define CAPN 8192u
#define PCAPN 16384u
static uint64_t rbase(GumCpuContext*c,int r){ if(r==31) return c->sp; if(r<29) return c->x[r]; if(r==29) return c->fp; return c->lr; }
static uint64_t rval (GumCpuContext*c,int r){ if(r==31) return 0;      if(r<29) return c->x[r]; if(r==29) return c->fp; return c->lr; }
static void on_store(GumCpuContext*c, gpointer u){
  SInfo* si=(SInfo*)u; uint64_t tgt=rbase(c,si->rn)+si->off;
  if(tgt<ALO||tgt>=AHI) return;
  uint32_t idx=RC; if(idx>=CAPN) return;
  RING[idx].pc=si->pc; RING[idx].tgt=tgt; RING[idx].vlo=rval(c,si->rt); RING[idx].vhi=si->pair?rval(c,si->rt2):0;
  RC=idx+1;
}
void transform(GumStalkerIterator*it, GumStalkerOutput*out, gpointer u){
  const cs_insn* insn;
  while(gum_stalker_iterator_next(it,&insn)){
    const char* mn=insn->mnemonic;
    if(mn[0]=='s'&&mn[1]=='t'&&(mn[2]=='r'||mn[2]=='p'||mn[2]=='u')){
      uint32_t w=insn->bytes[0]|(insn->bytes[1]<<8)|(insn->bytes[2]<<16)|((uint32_t)insn->bytes[3]<<24);
      int rn,rt,rt2=0,pair=0; int32_t off; int ok=1;
      if      ((w&0xFFC00000u)==0xF9000000u){ rn=(w>>5)&0x1F; rt=w&0x1F; off=((int32_t)((w>>10)&0xFFF))<<3; }
      else if ((w&0xFFC00000u)==0xA9000000u||(w&0xFFC00000u)==0xA9800000u){ rn=(w>>5)&0x1F; rt=w&0x1F; rt2=(w>>10)&0x1F; pair=1; int32_t i7=(w>>15)&0x7F; if(i7&0x40)i7|=~0x7F; off=i7<<3; }
      else if ((w&0xFFE00C00u)==0xF8000000u){ rn=(w>>5)&0x1F; rt=w&0x1F; int32_t i9=(w>>12)&0x1FF; if(i9&0x100)i9|=~0x1FF; off=i9; }
      else ok=0;
      if(ok){ uint32_t k=PN; if(k<PCAPN){ POOL[k].pc=(uint64_t)insn->address; POOL[k].off=off; POOL[k].rn=rn; POOL[k].rt=rt; POOL[k].rt2=rt2; POOL[k].pair=pair; PN=k+1;
              gum_stalker_iterator_put_callout(it,on_store,&POOL[k],0); } }
    }
    gum_stalker_iterator_keep(it);
  }
}
`, {});
let base=null,lo,hi,phase='idle',stid=0,caps=0; const learned={}; const chain={};
const SM3=0xa0748, SEEDGEN=0x10ac2c, IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hxab(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function readRing(){ const n=stateMem.readU32(); const recs=[];
  for(let i=0;i<n&&i<CAP;i++){ const b=ringMem.add(i*32); recs.push({pc:b.readU64(),tgt:b.add(8).readU64(),vlo:b.add(16).readU64(),vhi:b.add(24).readU64()}); } return recs; }
function u64hexLE(u){ let v=u.toString(16); while(v.length<16)v='0'+v; let o=''; for(let i=8;i>=1;i--)o+=v.substr((i-1)*2,2); return o; }
function capture(){
  const recs=readRing(); const hits=[];
  for(const r of recs){ const rvlo=u64hexLE(r.vlo),rvhi=u64hexLE(r.vhi); const full=rvlo+rvhi;
    if(learned[full]) hits.push({kind:'stp16',pc:'0x'+r.pc.sub(base).toString(16),tgt:'0x'+r.tgt.toString(16),val:full});
  }
  // also 8-byte halves
  for(const r of recs){ const rvlo=u64hexLE(r.vlo);
    for(const s in learned){ if(rvlo===s.slice(0,16)||rvlo===s.slice(16,32)){ hits.push({kind:'half',pc:'0x'+r.pc.sub(base).toString(16),tgt:'0x'+r.tgt.toString(16),val:rvlo,slot:s}); } } }
  if(recs.length>7000){ stateMem.writeU32(0); }
  send({t:'cap', ringN:recs.length, poolN:stateMem.add(4).readU32(), learnedN:Object.keys(learned).length,
        hits:hits.slice(0,16), sample:recs.slice(0,14).map(r=>({pc:'0x'+r.pc.sub(base).toString(16),tgt:'0x'+r.tgt.toString(16),vlo:u64hexLE(r.vlo),vhi:u64hexLE(r.vhi)}))});
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; lo=base; hi=base.add(m.size);
  Interceptor.attach(base.add(SM3),{onEnter(){ const tid=this.threadId; let st,inp;
    try{ st=hxab(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return; let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return; if(a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]); if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; }
    let slot='',pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    delete chain[tid]; if(slot!=='00'.repeat(16)&&pr<12){ learned[slot]=1; if(phase==='following') capture(); }
  }});
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(phase!=='idle') return;
    if(a[2].toInt32()!==16) return; let ra=null; try{ra=this.returnAddress;}catch(e){}
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0||ra.sub(base).toString(16)!=='a0440') return;
    const tid=this.threadId; stid=tid; phase='following';
    setImmediate(function(){ try{ stateMem.writeU32(0); stateMem.add(4).writeU32(0); Stalker.follow(stid,{transform:cm.transform}); send({t:'follow',tid:stid}); var mc=0; var iv=setInterval(function(){ mc++; send({t:'mon', poolN:stateMem.add(4).readU32(), ringN:stateMem.readU32(), learnedN:Object.keys(learned).length}); if(mc>=12){ clearInterval(iv); try{Stalker.unfollow(stid);Stalker.flush();}catch(e){} } },1000); }catch(e){ send({t:'err',msg:'follow '+e}); phase='idle'; } });
  }});
  send({t:'info',msg:'stalk-cm(v7b) installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
