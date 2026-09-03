// _scan_bl.js — Scan code for bl instructions targeting VM handler range
'use strict';
const SO = 'libmetasec_ov.so';

function scan() {
  const m = Process.findModuleByName(SO);
  if (!m) { setTimeout(scan, 200); return; }
  const base = m.base;

  // Scan range: main code section (0x50000-0x70000)
  const scanStart = 0x50000;
  const scanEnd = 0x70000;
  const size = scanEnd - scanStart;
  const code = new Uint8Array(base.add(scanStart).readByteArray(size));

  const handlerLo = 0xedec0;
  const handlerHi = 0xf87d8;

  let blCount = 0;
  let vmHandlerBlCount = 0;

  for (let i = 0; i < code.length - 4; i += 4) {
    const ins = (code[i] | (code[i+1] << 8) | (code[i+2] << 16) | (code[i+3] << 24)) >>> 0;

    // bl (immediate)
    if ((ins >>> 26) === 0x25) {
      const imm26 = ins & 0x3ffffff;
      const signed = imm26 << 6 >> 6;
      const target = (scanStart + i + signed) & 0xffffffff;
      blCount++;
      if (target >= handlerLo && target < handlerHi) {
        vmHandlerBlCount++;
        if (vmHandlerBlCount <= 30) {
          send({t:'bl_to_handler', src: 'SELF+0x' + (scanStart + i).toString(16),
                target: 'SELF+0x' + target.toString(16)});
        }
      }
    }
  }

  send({t:'info', msg: 'bl total=' + blCount + ' bl->VM-range=' + vmHandlerBlCount});

  // Also scan the OLLVM block range (0x55000-0x56000) specifically
  const ollvmStart = 0x55000;
  const ollvmEnd = 0x56000;
  const ollvmSize = ollvmEnd - ollvmStart;
  const ollvmCode = new Uint8Array(base.add(ollvmStart).readByteArray(ollvmSize));

  let ollvmBl = 0;
  let ollvmVmBl = 0;
  for (let i = 0; i < ollvmCode.length - 4; i += 4) {
    const ins = (ollvmCode[i] | (ollvmCode[i+1] << 8) | (ollvmCode[i+2] << 16) | (ollvmCode[i+3] << 24)) >>> 0;
    if ((ins >>> 26) === 0x25) {
      const imm26 = ins & 0x3ffffff;
      const signed = imm26 << 6 >> 6;
      const target = (ollvmStart + i + signed) & 0xffffffff;
      ollvmBl++;
      if (target >= handlerLo && target < handlerHi) {
        ollvmVmBl++;
        send({t:'ollvm_bl', src: 'SELF+0x' + (ollvmStart + i).toString(16),
              target: 'SELF+0x' + target.toString(16)});
      }
    }
  }
  send({t:'info', msg: 'OLLVM range bl=' + ollvmBl + ' bl->VM=' + ollvmVmBl});
}

if (Process.findModuleByName(SO)) {
  scan();
} else {
  Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
    onEnter(a) { try { this.p = a[0].readCString(); } catch(e) {} },
    onLeave() { if (this.p && this.p.indexOf(SO) >= 0) setTimeout(scan, 500); }
  });
}