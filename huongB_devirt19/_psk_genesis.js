'use strict';
// _psk_genesis.js — Capture the PSK "genesis": the decrypted .msp plaintext
// and correlate the live slot16 with the request query.
//
// Facts (static RE, libmetasec_ov.so):
//   * msp_loader @0x12f278 — the ONLY decrypt path (1 caller @0xde298).
//     Signature (AArch64, C++ sret): x0 = OUTPUT std::string* (caller's
//     x29-0x40), x1 = input filename std::string*. Plaintext lands at *x0.
//     (Old _psk_decrypt.js read `ret` — WRONG; result is via the x0 sret ptr.)
//   * concat @0x150348 — builds (query || slot16) for #19=SM3(...). x1 = slot16
//     std::string. Read here to tie a live slot16 to its query.
//
// Run:  frida -U -f com.zhiliaoapp.musically -l _psk_genesis.js --no-pause
//   or: frida -U com.zhiliaoapp.musically -l _psk_genesis.js   (attach)
const SO = 'libmetasec_ov.so';
let installed = false;

function hx(p, n){ try{ const u=new Uint8Array(p.readByteArray(n)); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return 'ERR'; } }
function asc(p, n){ try{ const u=new Uint8Array(p.readByteArray(n)); let s=''; for(let i=0;i<u.length;i++) s+=(u[i]>=32&&u[i]<127)?String.fromCharCode(u[i]):'.'; return s; }catch(e){ return 'ERR'; } }

// Read a libc++ std::string* -> {len, hex, ascii, isLong}
function readCxxString(p){
  try{
    const b0 = p.readU8();
    if((b0 & 1) === 0){                 // short/SSO: len=b0>>1, data at p+1
      const len = b0 >> 1;
      return { len:len, mode:'short', hex:hx(p.add(1), Math.min(len,22)), ascii:asc(p.add(1), Math.min(len,22)) };
    } else {                            // long: size at p+8, data ptr at p+16
      const len = p.add(8).readU64().toNumber();
      const dat = p.add(16).readPointer();
      const cap = Math.min(len, 256);
      return { len:len, mode:'long', hex:hx(dat, cap), ascii:asc(dat, cap) };
    }
  }catch(e){ return { err:String(e) }; }
}

function inst(base){
  if(installed) return; installed = true;
  send({ t:'info', msg:'genesis installed base='+base });

  // ── 1. PSK genesis: decrypted .msp plaintext ──
  Interceptor.attach(base.add(0x12f278), {
    onEnter(){ const c=this.context; this.out=c.x0; this.fn=c.x1;
      this.fname = readCxxString(c.x1); },
    onLeave(){
      const plain = readCxxString(this.out);
      send({ t:'PSK_GENESIS', file:this.fname, plaintext:plain });
    }
  });

  // ── 2. Live slot16 <-> query correlation ──
  let n=0;
  Interceptor.attach(base.add(0x150348), {
    onEnter(){ if(n>=40) return; n++; const c=this.context;
      const q = readCxxString(c.x0);        // query string
      const s = readCxxString(c.x1);        // slot16 (16 raw bytes as std::string)
      // slot16 is 16 raw bytes -> force-read 16 regardless of SSO detection
      let s16='';
      try{ const b0=c.x1.readU8();
        if((b0&1)===0) s16=hx(c.x1.add(1),16);
        else s16=hx(c.x1.add(16).readPointer(),16);
      }catch(e){}
      send({ t:'SLOT16_LIVE', n:n, slot16:s16,
             query_ascii:(q.ascii||'').slice(0,80), query_len:q.len });
    }
  });
}

const m = Process.findModuleByName(SO);
if(m) inst(m.base);
else{
  const dl = Module.findGlobalExportByName('android_dlopen_ext') || Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl, {
    onEnter(a){ try{ this.p=a[0].readCString(); }catch(e){} },
    onLeave(){ if(this.p && this.p.indexOf(SO)>=0){ const mm=Process.findModuleByName(SO); if(mm) inst(mm.base); } }
  });
  send({ t:'info', msg:'waiting for '+SO+' to load' });
}
