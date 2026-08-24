// A1: capture VM context at slot16-build (SM3 0xa0748). For each #19-message SM3 call
// (message ends ...||slot16(16)||0x30), dump regs x0-x28 + sp + stack[512] + input block ptr.
// Goal: locate the VM regfile / regfile[29] ratchet buffer to enable offline replay (Track A).
const m = Process.findModuleByName('libmetasec_ov.so');
if (!m) { send({t:'err',msg:'no libmetasec'}); }
else {
  const base = m.base, end = base.add(m.size);
  const SM3 = base.add(0xa0748);
  function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
  function rel(p){try{if(p.compare(base)>=0&&p.compare(end)<0)return 'so+0x'+p.sub(base).toString(16);}catch(e){}return p.toString();}
  // reconstruct #19 message from SM3 MD-chain: state_in==IV starts a new msg
  const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
  let cur=null, ncap=0;
  Interceptor.attach(SM3, { onEnter(a){
    // arg0=ctx (state at +8..+0x28), arg1=input(64B block)
    try{
      const ctx=a[0], inp=a[1];
      const st=hx(ctx.add(8),32);
      const blk=hx(inp,64);
      if(st===IV){ cur={blocks:[blk], ctx:this.context, sp:this.context.sp}; }
      else if(cur){ cur.blocks.push(blk); }
      // heuristic: last block of a #19 msg ends with slot16(16)+0x30 padded; capture context on FIRST block (entry)
      if(st===IV && cur && ncap<6){
        const c=this.context;
        const regs={};
        for(let i=0;i<=28;i++){try{regs['x'+i]=c['x'+i].toString();}catch(e){}}
        regs['sp']=c.sp.toString(); regs['fp']=c.fp?c.fp.toString():'';
        // dump stack 512B + a few candidate regfile derefs
        const stack=hx(c.sp,512);
        // regfile candidates: x19-x28 often hold VM state ptrs; dump 64B at each if it points into rw mem
        const derefs={};
        for(let i=19;i<=28;i++){ try{const p=c['x'+i]; const d=hx(p,64); if(d)derefs['x'+i+'->']=d;}catch(e){} }
        ncap++;
        send({t:'ENTRY', n:ncap, regs:regs, stack:stack, derefs:derefs, firstblk:blk});
      }
    }catch(e){ send({t:'err',msg:''+e}); }
  }});
  send({t:'info', msg:'A1 vmcap installed base='+base});
}
