#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_symexec.py — Unicorn-driven VM replay / disassemble-by-execution tracer for
# the libmetasec report-builder program 0x1814f0 (interp FUN_00152924 @0x52924).
#
# WHY: the pskVersion emit-decision (772 vs 408) lives inside this VM program, whose
# control flow is CFF-flattened via op44 (a computed dispatch). Static CFG cannot
# resolve it, so we run the REAL interpreter under Unicorn and observe the dispatch.
#
# KEY CORRECTION this tool established (vs prior notes): the runtime dispatch table
# uses handler(op) = table_base[op] - 0x9b374. _vm_static_decode.py used bias 0, so
# its handler VMAs were uniformly +0x9b374 PHANTOM addresses — the earlier
# "op44 = 0xedec0 computed-branch + sleep_for anti-emu" analysis was on the wrong
# function. REAL op44 handler = 0x52b4c, and it is a TWO-LEVEL dispatch escape:
# it re-reads the opcode word, extracts bits[11:6]=(word>>6)&0x3f, and dispatches
# through a 2nd table at *(0x1f00e8). There is no anti-emu sleep in op44.
#
# WHAT this build does:
#   * maps the .so at LOAD_BASE (+ vaddr mirror), like _vm_unicorn_replay.py;
#   * APPLIES all R_AARCH64_RELATIVE relocations as LOAD_BASE+addend (mandatory:
#     interp reads *(0x1f00e0) for its handler-table pointer);
#   * derives the real handler set from EMULATOR MEMORY (post-reloc), self-
#     correcting the bias, then hooks each handler VMA → logs the opcode stream;
#   * instruments op44's inner `br` (0x52bd0) → logs each nested opcode + target;
#   * resolves PLT stubs BY NAME (.rela.plt+.dynsym) → malloc = bump allocator,
#     rest = benign no-op;
#   * enters at the caller 0x95a3c (builds the exact 5-arg interp frame) with a
#     synthetic zeroed report-ctx + TPIDR/canary;
#   * guards the native-callout invoker (0x9b5d8): an unmodeled callout on
#     synthetic state returns 0 instead of branching through a null fn ptr, so the
#     trace runs the whole program shape (to trap/end).
#
# HONEST LIMIT: report emit happens through ~9 native callouts fn(self,data,len);
# their fn pointers only exist with a real ctx object graph. On synthetic state all
# callouts return 0, so the trace is the zero-state control flow — real material to
# map the program, but pinning the true pskVersion="0" path needs a captured interp
# entry-state or a phone differential (note 59 Phase 3 next).
#
# Run:  ~/.re-venv/bin/python _vm_symexec.py                    # trace prog 0x1814f0
#       ~/.re-venv/bin/python _vm_symexec.py --steps 40000 --verbose
import os, sys, struct, argparse

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL,
                     UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError)
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO        = "bin/libmetasec_ov.so"
LOAD_BASE = 0x6f5fe00000                      # same base convention as _vm_unicorn_replay.py
CALLER    = 0x95a3c                           # FUN_00195a3c: builds interp frame, bl 0x52924
INTERP    = 0x52924                           # FUN_00152924 (VM interpreter)
PROG      = 0x1814f0                           # report-builder program (what we trace)
# Runtime dispatch table (discovered by replay — NOT the biased static file):
#   table_base = (*(0x1f00e0) + f(0x52924)) & 2^64  = LOAD_BASE + 0x1d9488
#   handler(op) = table_base[op] - BIAS   (BIAS = [x29-0x58] = 0x9b374)
# The static _vm_static_decode.py table was uniformly +0x9b374 (phantom addrs),
# which is why the prior "op44=0xedec0 computed-branch+anti-emu" analysis was wrong.
RUNTIME_TABLE_VMA = 0x1d9488
DISPATCH_BIAS     = 0x9b374
# op44 (real handler 0x52b4c) is a TWO-LEVEL dispatch escape: it re-reads the
# opcode word, extracts bits[11:6] = (word>>6)&0x3f, and dispatches through a
# 2nd table at *(0x1f00e8). We log that nested op + resolved target at its `br`.
OP44_HANDLER = 0x52b4c
OP44_BR      = 0x52bd0                           # `br x15` — x15 = resolved 2nd-level handler
# VM native-callout invoker: ldp x3,x8,[x0]; ldp x1,x2,[x0,#0x10]; mov x0,x8; br x3.
# On synthetic state the fn ptr x3 is loaded from a zeroed slot ⇒ null callout.
# We guard the `br x3` so an unmodeled callout returns 0 (jump to x30 = VM
# re-dispatch) instead of branching to 0, letting the trace reveal program shape.
CALLOUT_BR = 0x9b5d8
OUT_TRACE = "../ground-truth/vm_symexec_1814f0_trace.txt"

MODULE_MAX      = 0x1fe1e0

# ---------------------------------------------------------------------------
# ELF parsing helpers
# ---------------------------------------------------------------------------
def parse_elf(so):
    e_phoff = struct.unpack_from("<Q", so, 0x20)[0]
    e_phes  = struct.unpack_from("<H", so, 0x36)[0]
    e_phn   = struct.unpack_from("<H", so, 0x38)[0]
    segs = []
    for i in range(e_phn):
        o = e_phoff + i * e_phes
        if struct.unpack_from("<I", so, o)[0] == 1:  # PT_LOAD
            p_off, p_va, _, p_fsz, p_msz = struct.unpack_from("<QQQQQ", so, o + 8)
            p_flags = struct.unpack_from("<I", so, o + 4)[0]
            segs.append((p_va, p_off, p_fsz, p_msz, p_flags))
    segs.sort()

    e_shoff = struct.unpack_from("<Q", so, 0x28)[0]
    e_shes  = struct.unpack_from("<H", so, 0x3a)[0]
    e_shn   = struct.unpack_from("<H", so, 0x3c)[0]
    secs = {}
    for i in range(e_shn):
        o = e_shoff + i * e_shes
        nm, typ, _, _, off, size, link, info, ent, es = struct.unpack_from("<IIQQQQIIQQ", so, o)
        secs[i] = dict(typ=typ, off=off, size=size, link=link, ent=es)
    return segs, secs

def seg_v2f(segs, v):
    for va, fo, fsz, msz, fl in segs:
        if va <= v < va + fsz:
            return fo + (v - va)
    return None

# ---------------------------------------------------------------------------
# Relocations (R_AARCH64_RELATIVE = 1027)
# ---------------------------------------------------------------------------
def collect_relatives(so, secs):
    out = []       # (r_off, r_add)
    for s in secs.values():
        if s["typ"] == 4:  # SHT_RELA
            for k in range(s["size"] // 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", so, s["off"] + k * 24)
                if (r_info & 0xffffffff) == 1027:
                    out.append((r_off, r_add))
    return out

def resolve_plt(so, secs):
    """Map PLT stub VMA -> symbol name via .rela.plt + .dynsym + .dynstr."""
    # locate by section type/order
    dynsym = dynstr = relaplt = plt = None
    for i, s in secs.items():
        if s["typ"] == 11: dynsym = s        # SHT_DYNSYM
        if s["typ"] == 3 and s["ent"] == 0 and s["link"] == 0 and s["size"] > 0x1000 and dynstr is None:
            pass
    # explicit: dynstr is the strtab linked from dynsym
    if dynsym is not None:
        dynstr = secs[dynsym["link"]]
    # .rela.plt = the SHT_RELA section whose link is dynsym and is the smaller one
    relas = [s for s in secs.values() if s["typ"] == 4]
    relas.sort(key=lambda s: s["size"])
    relaplt = relas[0] if relas else None
    # .plt = SHT_PROGBITS right after .rela.plt (we know base 0x30390 for this .so)
    PLT_BASE = 0x30390
    names = {}
    if not (dynsym and dynstr and relaplt):
        return names, PLT_BASE
    def symname(idx):
        so_off = dynsym["off"] + idx * 24
        n_off = struct.unpack_from("<I", so, so_off)[0]
        e = so.index(b"\0", dynstr["off"] + n_off)
        return so[dynstr["off"] + n_off:e].decode("latin1")
    n = relaplt["size"] // 24
    for k in range(n):
        r_off, r_info, r_add = struct.unpack_from("<QQq", so, relaplt["off"] + k * 24)
        sym_idx = r_info >> 32
        stub = PLT_BASE + 0x20 + k * 0x10   # AArch64: PLT0 header 0x20, entries 0x10
        names[stub] = symname(sym_idx)
    return names, PLT_BASE

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class VMSymExec:
    def __init__(self, max_steps=2500, verbose=False):
        self.max_steps = max_steps
        self.verbose = verbose
        self.so = open(SO, "rb").read()
        self.segs, self.secs = parse_elf(self.so)
        self.op_by_handler = {}      # handler_vma -> op   (derived from emulator memory)
        self.handler_by_op = {}      # op -> handler_vma
        self.trap = None
        self.plt_names, self.plt_base = resolve_plt(self.so, self.secs)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.trace = []          # (step, op, handler_vma, bcp)
        self.op44_log = []       # dicts
        self.step = 0
        self.stopped_reason = None
        # bump allocator arena
        self.heap_ptr = 0x4a000000
        self.heap_end = 0x4b000000
        # scratch regions
        self.TLS   = 0x5000_0000
        self.STACK = 0x6000_0000
        self.CTX   = 0x7000_0000   # synthetic report-ctx
        self.SENTINEL = 0x11110000  # fake return address (hooked → stop)

    # -- mapping -----------------------------------------------------------
    def _map_segments(self):
        page = 0xfff
        vaddr_end = 0
        for va, fo, fsz, msz, fl in self.segs:
            vaddr_end = max(vaddr_end, va + msz)
            for base in (0, LOAD_BASE):
                start = base + va
                aligned = start & ~page
                poff = start - aligned
                size = ((poff + msz + page) // 0x1000) * 0x1000
                try:
                    self.uc.mem_map(aligned, size, UC_PROT_ALL)
                except UcError:
                    pass
                if fsz > 0:
                    self.uc.mem_write(start, self.so[fo:fo + fsz])
        self.vaddr_end = vaddr_end
        self.so_end = LOAD_BASE + vaddr_end

    def _apply_relocations(self):
        # Standard loader semantics: *(LOAD_BASE + r_off) = LOAD_BASE + r_add for
        # EVERY R_AARCH64_RELATIVE. Large ("out-of-module") addends are legitimate:
        # e.g. the handler-table ptr addend 0x6b5fe0 is combined with f(x30) (a
        # near-2^64 value) and wraps back in-module. So we do NOT filter by range;
        # map-on-demand backs any high page that actually gets dereferenced.
        rels = collect_relatives(self.so, self.secs)
        applied = oor = 0
        for r_off, r_add in rels:
            val = (LOAD_BASE + r_add) & 0xffffffffffffffff
            if not (0 <= r_add < MODULE_MAX):
                oor += 1
            for base in (0, LOAD_BASE):
                try:
                    self.uc.mem_write(base + r_off, struct.pack("<Q", val))
                except UcError:
                    pass
            applied += 1
        return applied, oor, 0

    def _map_scratch(self):
        for a, sz in ((self.TLS, 0x10000), (self.STACK, 0x400000),
                      (self.CTX, 0x100000), (self.heap_ptr, self.heap_end - self.heap_ptr),
                      (self.SENTINEL & ~0xfff, 0x1000)):
            try:
                self.uc.mem_map(a & ~0xfff, ((sz + 0xfff) // 0x1000) * 0x1000, UC_PROT_ALL)
            except UcError:
                pass
        # canary at TLS+0x28
        self.uc.mem_write(self.TLS + 0x28, struct.pack("<Q", 0xCA1DECAFF00DBEEF))

    def _derive_handlers(self):
        """Read the real dispatch table out of emulator memory (post-relocation)."""
        from collections import Counter
        tb = LOAD_BASE + RUNTIME_TABLE_VMA
        raw = {}
        for op in range(64):
            ent = struct.unpack_from("<Q", self.uc.mem_read(tb + op * 8, 8))[0]
            h = (ent - DISPATCH_BIAS) & 0xffffffffffffffff
            raw[op] = h - LOAD_BASE if h >= LOAD_BASE else h
        self.trap = Counter(raw.values()).most_common(1)[0][0]
        self.handler_by_op = {op: h for op, h in raw.items() if h != self.trap}
        self.op_by_handler = {h: op for op, h in self.handler_by_op.items()}
        return len(self.handler_by_op)

    # -- hooks -------------------------------------------------------------
    def _bump(self, size):
        size = (size + 0xf) & ~0xf
        if size == 0:
            size = 0x10
        p = self.heap_ptr
        self.heap_ptr += size
        if self.heap_ptr >= self.heap_end:      # wrap; arena is big enough for a trace
            self.heap_ptr = 0x4a000000
            p = self.heap_ptr
            self.heap_ptr += size
        return p

    def _install_hooks(self):
        uc = self.uc

        # opcode-stream tracer: one hook over each real handler VMA (vaddr + absolute).
        # At handler entry, x23 = &bcp; *[x23] = bytecode ptr; *(*[x23]) = opcode word.
        def on_handler(uc, address, size, ud):
            vma = address if address < 0x200000 else address - LOAD_BASE
            op = self.op_by_handler.get(vma)
            if op is None:
                return
            self.step += 1
            x23 = uc.reg_read(UC_ARM64_REG_X23)
            word = op_hi = bcp = -1
            try:
                bcp = struct.unpack_from("<Q", uc.mem_read(x23, 8))[0]
                word = struct.unpack_from("<I", uc.mem_read(bcp, 4))[0]
                op_hi = (word >> 6) & 0x3f
            except UcError:
                pass
            bcpv = bcp - LOAD_BASE if bcp >= LOAD_BASE else bcp
            self.trace.append((self.step, op, op_hi, vma, bcpv, word))
            if self.verbose and self.step <= 100:
                print(f"  [{self.step:5d}] op{op:<2d} hi={op_hi:<2d} h=0x{vma:06x} "
                      f"bcp=0x{bcpv:x} word=0x{word:08x}")
            if self.step >= self.max_steps:
                self.stopped_reason = "max_steps"
                uc.emu_stop()

        for vma in self.op_by_handler:
            for base in (0, LOAD_BASE):
                uc.hook_add(UC_HOOK_CODE, on_handler, begin=base + vma, end=base + vma)

        # op44 nested-dispatch resolver — at 0x52bd0 (`br x15`), x15 = 2nd-level handler.
        def on_op44(uc, address, size, ud):
            x15 = uc.reg_read(UC_ARM64_REG_X15)
            x23 = uc.reg_read(UC_ARM64_REG_X23)
            tgt = x15 - LOAD_BASE if x15 >= LOAD_BASE else x15
            word = -1
            try:
                bcp = struct.unpack_from("<Q", uc.mem_read(x23, 8))[0]
                word = struct.unpack_from("<I", uc.mem_read(bcp, 4))[0]
            except UcError:
                pass
            op_hi = (word >> 6) & 0x3f if word >= 0 else -1
            self.op44_log.append(dict(step=self.step, op_hi=op_hi, target=tgt, word=word))
            if self.verbose and len(self.op44_log) <= 60:
                print(f"      · op44/nested #{len(self.op44_log)} hi={op_hi} "
                      f"-> 0x{tgt:x} word=0x{word:08x}")

        for base in (0, LOAD_BASE):
            uc.hook_add(UC_HOOK_CODE, on_op44, begin=base + OP44_BR, end=base + OP44_BR)

        # trap handler (dispatch table's most-common entry) — usually interp return/end.
        def on_trap(uc, address, size, ud):
            self.trap_hits += 1
            if self.trap_hits >= 3:
                self.stopped_reason = self.stopped_reason or "trap_repeated"
                uc.emu_stop()
        self.trap_hits = 0
        if self.trap is not None:
            for base in (0, LOAD_BASE):
                uc.hook_add(UC_HOOK_CODE, on_trap,
                            begin=base + self.trap, end=base + self.trap)

        # PLT stubs — malloc = bump alloc; free/sleep/etc = benign no-op
        def make_plt_hook(name):
            def h(uc, address, size, ud):
                if name in ("malloc", "calloc", "realloc",
                            "_Znwm", "_Znam"):           # operator new
                    req = uc.reg_read(UC_ARM64_REG_X0)
                    if name == "calloc":
                        req = req * uc.reg_read(UC_ARM64_REG_X1)
                    if name == "realloc":
                        req = uc.reg_read(UC_ARM64_REG_X1)
                    uc.reg_write(UC_ARM64_REG_X0, self._bump(req or 0x40))
                elif name in ("strlen",):
                    uc.reg_write(UC_ARM64_REG_X0, 0)
                elif name in ("memcpy", "memmove", "memset"):
                    pass  # leave x0 (dest) as return
                else:
                    uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
            return h

        for stub, name in self.plt_names.items():
            for base in (0, LOAD_BASE):
                uc.hook_add(UC_HOOK_CODE, make_plt_hook(name),
                            begin=base + stub, end=base + stub)

        # native-callout invoker guard — `br x3` at 0x9b5d8; if x3 is not a valid
        # code target (unmodeled callout on synthetic state) → return 0 to x30.
        self.callouts = 0
        self.null_callouts = 0
        self.callout_log = []
        def on_callout(uc, address, size, ud):
            self.callouts += 1
            x3 = uc.reg_read(UC_ARM64_REG_X3)   # native fn ptr (loaded from [x0])
            x0 = uc.reg_read(UC_ARM64_REG_X0)   # already = x8 (self/arg)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            v3 = x3 - LOAD_BASE if x3 >= LOAD_BASE else x3
            valid = (LOAD_BASE + 0x1000) <= x3 < self.so_end   # inside .so code image
            bcp = -1
            try:
                p = struct.unpack_from("<Q", uc.mem_read(uc.reg_read(UC_ARM64_REG_X23), 8))[0]
                bcp = p - LOAD_BASE if p >= LOAD_BASE else p
            except UcError:
                pass
            self.callout_log.append(dict(step=self.step, bcp=bcp, fn=v3, valid=valid,
                                         x0=x0, x1=x1, x2=x2))
            if not valid:
                self.null_callouts += 1
                uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
                if self.verbose and self.null_callouts <= 30:
                    print(f"      ! null-callout #{self.null_callouts} @step {self.step} "
                          f"bcp=0x{bcp:x} x3=0x{v3:x} → return 0")
        for base in (0, LOAD_BASE):
            uc.hook_add(UC_HOOK_CODE, on_callout, begin=base + CALLOUT_BR, end=base + CALLOUT_BR)

        # sentinel return → stop
        def on_sentinel(uc, address, size, ud):
            self.stopped_reason = self.stopped_reason or "returned_to_sentinel"
            uc.emu_stop()
        uc.hook_add(UC_HOOK_CODE, on_sentinel,
                    begin=self.SENTINEL, end=self.SENTINEL)

        # map-on-demand for stray reads/writes (synthetic state)
        self.faults = 0
        def on_unmapped(uc, access, address, size, value, ud):
            page = address & ~0xfff
            try:
                uc.mem_map(page, 0x1000, UC_PROT_ALL)
                self.faults += 1
                return True
            except UcError:
                return False
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

    # -- run ---------------------------------------------------------------
    def setup(self):
        print(f"[*] .so {SO} ({len(self.so)} bytes)  LOAD_BASE=0x{LOAD_BASE:x}")
        self._map_segments()
        app, oor, _ = self._apply_relocations()
        print(f"[*] relocations applied={app} (out-of-module addend={oor}, standard LOAD_BASE+add)")
        nh = self._derive_handlers()
        print(f"[*] runtime dispatch table @0x{RUNTIME_TABLE_VMA:x} bias=0x{DISPATCH_BIAS:x}: "
              f"{nh} real handlers, trap=0x{self.trap:x}")
        print(f"[*] PLT symbols resolved: {len(self.plt_names)}")
        self._map_scratch()
        self._install_hooks()
        uc = self.uc
        # register state for entering the caller 0x95a3c
        sp = self.STACK + 0x200000
        uc.reg_write(UC_ARM64_REG_SP, sp)
        uc.reg_write(UC_ARM64_REG_FP, sp)
        uc.reg_write(UC_ARM64_REG_LR, self.SENTINEL)
        uc.reg_write(UC_ARM64_REG_X0, self.CTX)          # synthetic report-ctx
        # TPIDR_EL0 (TLS) — 0x95a3c reads tpidr + [tls+0x28] canary
        try:
            uc.reg_write(UC_ARM64_REG_TPIDR_EL0, self.TLS)
        except Exception:
            pass
        # confirm the interp handler-table pointer resolved
        try:
            tp = struct.unpack_from("<Q", uc.mem_read(LOAD_BASE + 0x1f00e0, 8))[0]
            print(f"[*] *(0x1f00e0) = 0x{tp:x}  (expect LOAD_BASE+0x6b5fe0=0x{LOAD_BASE+0x6b5fe0:x})")
        except UcError:
            pass

    def run(self):
        entry = LOAD_BASE + CALLER
        print(f"[*] entering caller 0x{CALLER:x} (→ interp 0x{INTERP:x}, prog 0x{PROG:x})")
        try:
            self.uc.emu_start(entry, self.SENTINEL, timeout=60_000_000, count=8_000_000)
        except UcError as e:
            self.stopped_reason = self.stopped_reason or f"UcError:{e}"
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            vpc = pc - LOAD_BASE if pc >= LOAD_BASE else pc
            print(f"[!] emu stop @pc=0x{vpc:x} ({e})")
        except Exception as e:
            self.stopped_reason = self.stopped_reason or f"Exc:{e}"
        self._report()

    # -- report ------------------------------------------------------------
    def _report(self):
        from collections import Counter
        print(f"\n[=] stopped: {self.stopped_reason}  handler-steps={len(self.trace)}  "
              f"op44-nested={len(self.op44_log)}  callouts={self.callouts} "
              f"(null={self.null_callouts})  on-demand-faults={self.faults}")
        hist = Counter(op for _, op, _, _, _, _ in self.trace)
        print("[=] executed-opcode histogram:",
              ", ".join(f"op{op}×{c}" for op, c in hist.most_common(14)))
        nested = Counter(e["op_hi"] for e in self.op44_log)
        if nested:
            print("[=] op44 nested-opcode histogram:",
                  ", ".join(f"hi{op}×{c}" for op, c in nested.most_common(14)))
        with open(OUT_TRACE, "w") as f:
            f.write(f"# _vm_symexec.py trace — prog 0x{PROG:x}, interp 0x{INTERP:x}\n")
            f.write(f"# runtime table @0x{RUNTIME_TABLE_VMA:x} bias=0x{DISPATCH_BIAS:x} "
                    f"trap=0x{self.trap:x}\n")
            f.write(f"# stopped={self.stopped_reason} steps={len(self.trace)} "
                    f"op44-nested={len(self.op44_log)} faults={self.faults}\n\n")
            f.write("## handler-dispatch stream (step  op  hi  handler  bcp  word)\n")
            for st, op, hi, h, bcp, word in self.trace:
                f.write(f"{st:6d}  op{op:<2d} hi{hi:<2d}  0x{h:06x}  "
                        f"bcp=0x{bcp:x}  word=0x{word:08x}\n")
            f.write("\n## op44 nested-dispatch resolutions (2nd-level opcode -> handler)\n")
            for e in self.op44_log:
                f.write(f"step={e['step']} hi={e['op_hi']} -> 0x{e['target']:x} "
                        f"word=0x{e['word']:08x}\n")
            f.write("\n## native call-outs (invoker 0x9b5cc; fn ptr from ctx graph)\n")
            for e in self.callout_log:
                f.write(f"step={e['step']} bcp=0x{e['bcp']:x} fn=0x{e['fn']:x} "
                        f"valid={e['valid']} x0=0x{e['x0']:x} x1=0x{e['x1']:x} x2=0x{e['x2']:x}\n")
        print(f"[=] full trace written → {OUT_TRACE}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", type=int, default=2500, help="max handler dispatches to trace")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    eng = VMSymExec(max_steps=a.steps, verbose=a.verbose)
    eng.setup()
    eng.run()


if __name__ == "__main__":
    main()
