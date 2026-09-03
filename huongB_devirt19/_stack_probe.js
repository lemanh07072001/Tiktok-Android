'use strict';
const SO = 'libmetasec_ov.so';
const VM_ENTRY = 0x55950;
const m = Process.findModuleByName(SO);
const base = m.base;
let hits = 0;

Interceptor.attach(base.add(VM_ENTRY), {
  onEnter() {
    hits++;
    if (hits > 5) return;
    const ctx = this.context;
    const saved_x25 = ctx.sp.add(0x50).readU64();
    const saved_x5 = ctx.sp.add(0x10).readU64();
    const saved_x6 = ctx.sp.add(0x18).readU64();
    const sp38 = ctx.sp.add(0x38).readU64();
    const sp40 = ctx.sp.add(0x40).readU64();
    send({
      n: hits,
      sp: ctx.sp.toString(16),
      cpu_x25: ctx.x25.toString(16),
      saved_x25_50: saved_x25.toString(16),
      saved_x27_40: sp40.toString(16),
      saved_x5_10: saved_x5.toString(16),
      saved_x6_18: saved_x6.toString(16),
      sp38: sp38.toString(16),
    });
  }
});
send({ t: 'info', msg: 'Stack probe installed' });