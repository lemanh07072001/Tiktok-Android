// _disasm_live.js — disassemble a vaddr range from the DECRYPTED runtime memory of libmetasec_ov.so
'use strict';
const SO='libmetasec_ov.so';
const RANGES=[[0x59610,0x59690],[0x58b40,0x58bc0],[0x52cf0,0x52d50],[0x53510,0x535a0],[0x557a0,0x55840],[0x55560,0x555f0]]; // ALU handlers: load-imm, OR-insert, shift, rotate, mix, mix
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base;
  for(const [lo,hi] of RANGES){
    const out=[];
    let a=base.add(lo); const end=base.add(hi);
    while(a.compare(end)<0){
      let ins; try{ ins=Instruction.parse(a); }catch(e){ out.push((a.sub(base))+' <undecodable>'); a=a.add(4); continue; }
      let mark='';
      if(ins.mnemonic==='bl'||ins.mnemonic==='blr') mark=' <-- '+ins.mnemonic.toUpperCase();
      if(ins.mnemonic==='stp'&&/x29.*x30/.test(ins.opStr)) mark=' <== PROLOGUE';
      if(/^st/.test(ins.mnemonic)) mark=mark||' [store]';
      out.push('0x'+a.sub(base).toString(16)+'  '+ins.mnemonic+' '+ins.opStr+mark);
      a=ins.next;
    }
    send({t:'dis', lo:lo, hi:hi, lines:out});
  }
  send({t:'info',msg:'disasm done'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
