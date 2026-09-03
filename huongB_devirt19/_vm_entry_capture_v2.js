/**
 * _vm_entry_capture_v2.js — enhanced VM entry state capture at 0x55950.
 * Captures ALL registers (x0-x28), regfile, bytecode, callback ptr, and control struct.
 *
 * Run: frida -U -l _vm_entry_capture_v2.js <musically-PID>
 * Save output: frida -U -l _vm_entry_capture_v2.js <musically-PID> -o capture_v2.json
 */
'use strict';

const SO = 'libmetasec_ov.so';
const VM_ENTRY = 0x55950;

let vmHits = 0;

function hx(ab) {
  const u = new Uint8Array(ab);
  let s = '';
  for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
  return s;
}

function safeReadPtr(ptr, size) {
  try {
    if (ptr.isNull()) return 'NULL';
    return hx(ptr.readByteArray(size));
  } catch (e) { return 'ERR:' + e.message; }
}

function safeReadU64(ptr) {
  try {
    if (ptr.isNull()) return 'NULL';
    return ptr.readU64().toString(16).padStart(16, '0');
  } catch (e) { return 'ERR:' + e.message; }
}

function safeReadU32(ptr) {
  try {
    if (ptr.isNull()) return 'NULL';
    return ptr.readU32().toString(16).padStart(8, '0');
  } catch (e) { return 'ERR:' + e.message; }
}

function reg(h, name) {
  try {
    if (h === undefined || h === null) return 'UNDEF';
    return h.toString(16);
  } catch (e) { return 'ERR:' + e.message; }
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  const base = m.base;

  Interceptor.attach(base.add(VM_ENTRY), {
    onEnter() {
      vmHits++;
      const ctx = this.context;
      const n = vmHits;

      // ── ALL CPU registers x0-x28 ──
      const regs = {};
      for (let i = 0; i <= 28; i++) {
        try {
          regs['x' + i] = ctx['x' + i].toString(16);
        } catch (e) { regs['x' + i] = 'ERR'; }
      }
      regs.fp = reg(ctx.fp, 'fp');
      regs.lr = reg(ctx.lr, 'lr');
      regs.sp = reg(ctx.sp, 'sp');

      // ── VM register file (x24 -> 32 x 8-byte slots) ──
      let regfile = '';
      try {
        for (let i = 0; i < 32; i++) {
          regfile += safeReadU64(ctx.x24.add(i * 8));
        }
      } catch (e) { regfile = 'ERROR: ' + e.message; }

      // ── Bytecode (x23 is ptr-to-ptr, read full 256 bytes) ──
      let bytecode = '';
      let bcPtr = 'NULL';
      try {
        bcPtr = ctx.x23.readPointer();
        bytecode = safeReadPtr(bcPtr, 256);
      } catch (e) { bytecode = 'ERROR: ' + e.message; }

      // ── Callback function pointer at *R[22] (x22 in CPU = R[22] in VM?) ──
      // R[22] = 0x70e6c592b8 (heap). Try to read *R[22]
      let callbackPtr = 'NULL';
      let callbackCode = 'NULL';
      try {
        // x22 in CPU regs might be R[22] from the VM regfile
        const r22 = ctx.x22;
        if (!r22.isNull()) {
          callbackPtr = safeReadU64(r22);  // *R[22] = function pointer
          // Try to read 64 bytes of code at the callback
          const cbAddr = r22.readU64();
          if (cbAddr && !cbAddr.isNull && cbAddr.compare(0) !== 0) {
            try {
              callbackCode = hx(ptr(cbAddr).readByteArray(64));
            } catch (e) { callbackCode = 'ERR:' + e.message; }
          }
        }
      } catch (e) { callbackPtr = 'ERR:' + e.message; }

      // ── Control structure at x25 (R[25]) ──
      // Key fields: +0x60 (mapping table ptr), +0x6c (size), +0x70 (flags), +0xb8 (reg count)
      let ctlStruct = {};
      try {
        const x25 = ctx.x25;
        if (!x25.isNull()) {
          ctlStruct.b8_regcount = safeReadU32(x25.add(0xb8));
          ctlStruct.map_ptr = safeReadU64(x25.add(0x60));
          ctlStruct.map_size = safeReadU32(x25.add(0x6c));
          ctlStruct.flags_32 = safeReadPtr(x25.add(0x70), 32);
          // Try to read the mapping table (first 32 entries)
          const mapPtr = x25.add(0x60).readU64();
          ctlStruct.map_data = safeReadPtr(mapPtr, 128);
          // Read the flag bytes
          ctlStruct.flags_data = safeReadPtr(x25.add(0x70), 64);
        }
      } catch (e) { ctlStruct.error = e.message; }

      // ── Output buffer at x28 (R[28]) ──
      let outputBuf = '';
      try {
        const x28 = ctx.x28;
        if (!x28.isNull()) {
          outputBuf = safeReadPtr(x28, 64);
        }
      } catch (e) { outputBuf = 'ERR:' + e.message; }

      // ── Stride table at *(x20 + 0x10) used by opcode 44 ──
      let strideTable = {};
      try {
        const x20 = ctx.x20;
        if (!x20.isNull()) {
          const stridePtr = x20.add(0x10).readU64();
          strideTable.base = safeReadU64(stridePtr);
          strideTable.stride = safeReadU32(stridePtr.add(8));
        }
      } catch (e) { strideTable.error = e.message; }

      // ── Stack values (saved x5, x6 at sp+0x10, sp+0x18) ──
      let stackVals = {};
      try {
        stackVals.saved_x5 = safeReadU64(ctx.sp.add(0x10));
        stackVals.saved_x6 = safeReadU64(ctx.sp.add(0x18));
        stackVals.sp_0x08 = safeReadU64(ctx.sp.add(8));
        stackVals.sp_0x28 = safeReadU64(ctx.sp.add(0x28));
        stackVals.sp_0x30 = safeReadU64(ctx.sp.add(0x30));
        stackVals.sp_0x38 = safeReadU64(ctx.sp.add(0x38));
      } catch (e) { stackVals.error = e.message; }

      send({
        t: 'vm_entry_v2',
        n: n,
        base: base.toString(16),
        regs: regs,
        regfile: regfile,
        bytecode256: bytecode,
        bcPtr: bcPtr.toString(16),
        callbackPtr: callbackPtr,
        callbackCode: callbackCode,
        ctlStruct: ctlStruct,
        outputBuf: outputBuf,
        strideTable: strideTable,
        stackVals: stackVals,
      });

      // Stop after 10 captures (enough to see pattern)
      if (vmHits >= 10) {
        send({ t: 'info', msg: 'Captured 10 VM entries, detaching...' });
      }
    }
  });

  send({ t: 'info', msg: 'VM entry capture v2 installed at base=' + base });
  return true;
}

if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a) { try { this.p = a[0].readCString(); } catch (e) {} },
  onLeave() { if (this.p && this.p.indexOf(SO) >= 0) install(); }
});