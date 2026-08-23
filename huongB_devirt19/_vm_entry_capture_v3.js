/**
 * _vm_entry_capture_v3.js — FIXED: reads VM registers from regfile (x24), not CPU regs.
 * At VM entry (0x55950), CPU x19-x28 are NOT the VM register values yet.
 * The VM register file at *x24 holds the real state: R[20]=stride, R[22]=callback, R[25]=ctlStruct, R[28]=outBuf.
 *
 * Run: frida -U -l _vm_entry_capture_v3.js <musically-PID> -o capture_v3.json
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

function readVmReg(ctx, idx) {
  try {
    return ctx.x24.add(idx * 8).readU64();
  } catch (e) { return null; }
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

      // ── CPU registers (x0-x28 for dispatch context) ──
      const cpur = {};
      for (let i = 0; i <= 28; i++) {
        try { cpur['x' + i] = ctx['x' + i].toString(16); }
        catch (e) { cpur['x' + i] = 'ERR'; }
      }
      cpur.fp = ctx.fp.toString(16);
      cpur.lr = ctx.lr.toString(16);
      cpur.sp = ctx.sp.toString(16);

      // ── VM register file (x24 -> 32 x 8-byte slots) ──
      let regfile = '';
      let vmRegs = []; // parsed VM register values as NativePointer
      try {
        for (let i = 0; i < 32; i++) {
          const val = ctx.x24.add(i * 8).readU64();
          regfile += val.toString(16).padStart(16, '0');
          vmRegs.push(val);
        }
      } catch (e) { regfile = 'ERROR: ' + e.message; }

      // ── Bytecode (x23 is ptr-to-ptr) ──
      let bytecode = '';
      let bcPtr = 'NULL';
      try {
        bcPtr = ctx.x23.readPointer();
        bytecode = safeReadPtr(bcPtr, 256);
      } catch (e) { bytecode = 'ERROR: ' + e.message; }

      // ── Callback function pointer at *R[22] (from regfile, not CPU) ──
      let callbackPtr = 'NULL';
      let callbackCode = 'NULL';
      try {
        const r22 = vmRegs[22];
        if (r22 && r22.compare(0) !== 0) {
          callbackPtr = safeReadU64(ptr(r22));   // *R[22] = fn pointer
          // Read 64 bytes of code at the callback
          try {
            const cbAddr = ptr(r22).readU64();
            if (cbAddr.compare(0) !== 0) {
              callbackCode = safeReadPtr(ptr(cbAddr), 64);
            }
          } catch (ee) { callbackCode = 'ERR2:' + ee.message; }
        }
      } catch (e) { callbackPtr = 'ERR:' + e.message; }

      // ── Control structure at R[25] (from regfile, not CPU) ──
      let ctlStruct = {};
      try {
        const r25 = vmRegs[25];
        if (r25 && r25.compare(0) !== 0) {
          const p25 = ptr(r25);
          ctlStruct.r25 = r25.toString(16).padStart(16, '0');
          ctlStruct.b8_regcount = safeReadU32(p25.add(0xb8));
          ctlStruct.map_ptr = safeReadU64(p25.add(0x60));
          ctlStruct.map_size = safeReadU32(p25.add(0x6c));
          ctlStruct.flags_data = safeReadPtr(p25.add(0x70), 64);
          // Read mapping table contents
          try {
            const mapPtr = p25.add(0x60).readU64();
            if (mapPtr.compare(0) !== 0) {
              ctlStruct.map_data = safeReadPtr(ptr(mapPtr), 128);
            }
          } catch (ee) { ctlStruct.map_data = 'ERR2:' + ee.message; }
        }
      } catch (e) { ctlStruct.error = e.message; }

      // ── Output buffer at R[28] (from regfile) ──
      let outputBuf = '';
      try {
        const r28 = vmRegs[28];
        if (r28 && r28.compare(0) !== 0) {
          outputBuf = safeReadPtr(ptr(r28), 64);
        }
      } catch (e) { outputBuf = 'ERR:' + e.message; }

      // ── Stride table at *(R[20] + 0x10) (from regfile) ──
      let strideTable = {};
      try {
        const r20 = vmRegs[20];
        if (r20 && r20.compare(0) !== 0) {
          const stridePtr = ptr(r20).add(0x10).readU64();
          if (stridePtr.compare(0) !== 0) {
            strideTable.base = safeReadU64(ptr(stridePtr));
            strideTable.stride = safeReadU32(ptr(stridePtr).add(8));
          }
        }
      } catch (e) { strideTable.error = e.message; }

      // ── Stack values ──
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
        t: 'vm_entry_v3',
        n: n,
        base: base.toString(16),
        cpur: cpur,
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

      if (vmHits >= 15) {
        send({ t: 'info', msg: 'Captured 15 VM entries, stopping...' });
      }
    }
  });

  send({ t: 'info', msg: 'VM entry capture v3 installed at base=' + base });
  return true;
}

if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a) { try { this.p = a[0].readCString(); } catch (e) {} },
  onLeave() { if (this.p && this.p.indexOf(SO) >= 0) install(); }
});