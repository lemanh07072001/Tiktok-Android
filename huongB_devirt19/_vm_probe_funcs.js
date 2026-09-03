// _vm_probe_funcs.js — Read first 0x80 bytes of the dispatched functions
'use strict';

const SO = 'libmetasec_ov.so';
const PROBE_ADDRS = [
  { off: 0x116B64, name: 'fn_116B64' },
  { off: 0x17A308, name: 'fn_17A308' },
  { off: 0x14FA94, name: 'fn_14FA94' },
  { off: 0x14FE34, name: 'fn_14FE34' },
  // Also probe a few dispatch table handler addresses
  { off: 0xF04AC, name: 'handler_ARX_ror' },
  { off: 0xF87D8, name: 'handler_cbnz' },
  { off: 0xF4F8C, name: 'handler_most_common' },
];

function hx(ab) {
  const u = new Uint8Array(ab);
  let s = '';
  for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
  return s;
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  const base = m.base;

  send({ t: 'info', base: base.toString() });

  for (const p of PROBE_ADDRS) {
    try {
      const addr = base.add(p.off);
      const code = hx(addr.readByteArray(0x80));
      send({ t: 'code', name: p.name, off: 'SELF+0x' + p.off.toString(16), code: code });
    } catch(e) {
      send({ t: 'error', name: p.name, err: e.toString() });
    }
  }

  send({ t: 'done' });
}

if (Process.findModuleByName(SO)) {
  install();
} else {
  Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
    onEnter(a) { try { this.p = a[0].readCString(); } catch(e) {} },
    onLeave() { if (this.p && this.p.indexOf(SO) >= 0) setTimeout(install, 200); }
  });
}