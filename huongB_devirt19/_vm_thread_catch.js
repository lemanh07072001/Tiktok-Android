// _vm_thread_catch.js — catch the VM thread's registers WITHOUT hooking/patching code.
// Uses Process.enumerateThreads() (read-only register snapshot) polled rapidly. When a thread's
// PC is inside the VM function [base+0x52924, base+0x5d484], dump its full context + regfile.
// No Interceptor.attach on metasec code => no self-integrity trip / SafeMode.
'use strict';
const SO = 'libmetasec_ov.so';
const VM_LO = 0x52924, VM_HI = 0x5d484;

function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}

let base = null, caught = 0, scans = 0, running = true;
const MAX_CATCH = 6, MAX_SCANS = 2000000;

function scan(){
  if (!running) return;
  scans++;
  try {
    const ths = Process.enumerateThreads();
    for (let i=0;i<ths.length;i++){
      const t = ths[i]; const ctx = t.context;
      if (!ctx || !ctx.pc) continue;
      const pc = ctx.pc.sub(base);
      const off = pc.toInt32 ? pc.toInt32() : parseInt(pc.toString(),16);
      // pc.sub(base) is a NativePointer; compare via unsigned
      const pcv = ctx.pc.toString();
      const b = base;
      if (ctx.pc.compare(b.add(VM_LO))>=0 && ctx.pc.compare(b.add(VM_HI))<0){
        // caught VM thread
        const regs = {};
        ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','fp','lr','sp','pc'].forEach(r=>{
          try{ regs[r] = ctx[r].toString(); }catch(e){ regs[r]='?'; }
        });
        let regfile='', r29buf='';
        try { regfile = hx(ctx.x24.readByteArray(256)); } catch(e){ regfile='ERR:'+e.message; }
        try { const r29 = ctx.x24.add(29*8).readU64(); regfile && (regs.r29ptr = r29.toString(16));
              r29buf = hx(ptr(r29).sub(64).readByteArray(512)); } catch(e){ r29buf='ERR'; }
        caught++;
        send({ t:'catch', n:caught, pc_off: '0x'+ctx.pc.sub(b).toString(16), tid: t.id,
               regs: regs, regfile: regfile, r29buf: r29buf });
        if (caught >= MAX_CATCH){ running=false; send({t:'info',msg:'caught '+caught+', stopping. scans='+scans}); return; }
      }
    }
  } catch(e){}
  if (scans < MAX_SCANS && running) setImmediate(scan);
  else if (running){ running=false; send({t:'info',msg:'scans exhausted='+scans+' caught='+caught}); }
}

function start(){
  const m = Process.findModuleByName(SO);
  if (!m){ send({t:'info',msg:'metasec not found'}); return; }
  base = m.base;
  send({t:'info',msg:'catcher started base='+base+' VM=['+VM_LO.toString(16)+','+VM_HI.toString(16)+']'});
  scan();
}
start();
