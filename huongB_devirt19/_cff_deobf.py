#!/usr/bin/env python3
# _cff_deobf.py — CFF deobfuscator for libmetasec_ov native .text (readable, CFF-obfuscated).
# Core: concrete block-emulator that tracks GP regs + sp-relative stack slots, resolving the
# opaque-predicate computed branches (br xN after csel/adrp/madd). Reconstructs the real CFG so we
# can trace slot16 (the header field read by 0x9fd74 / query-assembly) back to its writer F.
import json, sys
from capstone import *
from capstone.arm64 import *

import os
_MF = '_code_dump_full.bin' if os.path.exists('_code_dump_full.bin') else '_code_dump.bin'
_MM = '_code_dump_full_meta.json' if os.path.exists('_code_dump_full_meta.json') else '_code_dump_meta.json'
meta = json.load(open(_MM))
BASE = int(meta['base'], 16)
DATA = open(_MF, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
MASK = (1 << 64) - 1

def rd4(off): return int.from_bytes(DATA[off:off+4], 'little')

class State:
    def __init__(s):
        s.r = {}          # reg-name -> int (concrete) or None (unknown)
        s.stk = {}        # sp-offset -> int or None
        s.flags = None    # (a,b) last cmp operands (concrete) or None
    def copy(s):
        t = State(); t.r = dict(s.r); t.stk = dict(s.stk); t.flags = s.flags; return t
    def get(s, name):
        if name in ('xzr', 'wzr'): return 0
        if name.startswith('w'):
            x = s.r.get('x'+name[1:], None)
            return None if x is None else (x & 0xffffffff)
        return s.r.get(name, None)
    def setx(s, name, val):
        if name in ('xzr', 'wzr'): return
        if name.startswith('w'):
            s.r['x'+name[1:]] = None if val is None else (val & 0xffffffff)
        else:
            s.r[name] = None if val is None else (val & MASK)

def opregs(ins):
    return [ins.reg_name(o.reg) if o.type == ARM64_OP_REG else o for o in ins.operands]

def emulate_block(start_off, maxins=200):
    """start_off = MODULE OFFSET. Emulate at real VA (BASE+off) so adrp resolves. Return
    (term_va, [successor_VAs], mnem, note). Successors are VAs; caller converts to offsets."""
    st = State()
    off = start_off; va = BASE + start_off
    ins_list = list(md.disasm(DATA[off:off+maxins*4], va))
    for i, ins in enumerate(ins_list):
        m = ins.mnemonic; ops = ins.operands
        def R(idx): return ins.reg_name(ops[idx].reg)
        def IMM(idx): return ops[idx].imm
        try:
            if m in ('b',):
                return (ins.address, [IMM(0)], m, 'direct')
            if m in ('br',):
                t = st.get(R(0))
                if t is not None:
                    return (ins.address, [t], m, 'br %s=0x%x'%(R(0), t-BASE))
                cs = st.r.get('__csel__')
                if cs and cs[0]==R(0) and cs[1] is not None and cs[2] is not None:
                    return (ins.address, [cs[1], cs[2]], m, 'br %s=csel(0x%x,0x%x)'%(R(0), cs[1]-BASE, cs[2]-BASE))
                return (ins.address, [], m, 'br %s=UNRESOLVED'%R(0))
            if m in ('ret',):
                return (ins.address, [], m, 'ret')
            if m in ('blr','bl'):
                # call: continue to fallthrough; record callee if known
                callee = st.get(R(0)) if m=='blr' else IMM(0)
                st.setx('x0', None)  # return value unknown
                # fallthrough
                nxt = ins.address + 4
                st.setx('lr', nxt)
                # keep going (not a block terminator for CFG-of-this-func, but note the call)
                continue
            if m.startswith('b.') or m in ('cbz','cbnz','tbz','tbnz'):
                tgt = IMM(len(ops)-1)
                fall = ins.address + 4
                return (ins.address, [tgt, fall], m, 'cond')
            # data-processing
            if m in ('mov','movz'):
                if ops[1].type == ARM64_OP_IMM: st.setx(R(0), IMM(1))
                elif ops[1].type == ARM64_OP_REG: st.setx(R(0), st.get(R(1)))
                else: st.setx(R(0), None)
            elif m == 'movk':
                cur = st.get(R(0)); sh = ops[1].shift.value if ops[1].shift.type else 0
                imm = IMM(1)
                if cur is None: cur = 0
                st.setx(R(0), (cur & ~(0xffff << sh)) | (imm << sh))
            elif m == 'adrp':
                st.setx(R(0), IMM(1))  # capstone resolves absolute page
            elif m in ('add','sub'):
                a = st.get(R(1))
                b = IMM(2) if ops[2].type == ARM64_OP_IMM else st.get(R(2))
                if a is None or b is None: st.setx(R(0), None)
                else: st.setx(R(0), a+b if m=='add' else a-b)
            elif m in ('and','orr','orn','eor','bic'):
                a = st.get(R(1))
                b = IMM(2) if ops[2].type == ARM64_OP_IMM else st.get(R(2))
                if a is None or b is None: st.setx(R(0), None)
                else:
                    if m=='and': v=a&b
                    elif m=='orr': v=a|b
                    elif m=='orn': v=a|((~b)&MASK)
                    elif m=='eor': v=a^b
                    elif m=='bic': v=a&((~b)&MASK)
                    st.setx(R(0), v)
            elif m in ('madd','msub'):
                a=st.get(R(1)); b=st.get(R(2)); c=st.get(R(3))
                if None in (a,b,c): st.setx(R(0), None)
                else: st.setx(R(0), (c+a*b) if m=='madd' else (c-a*b))
            elif m in ('mul',):
                a=st.get(R(1)); b=st.get(R(2))
                st.setx(R(0), None if (a is None or b is None) else a*b)
            elif m in ('csel','csinc','csinv','csneg'):
                a=st.get(R(1)); b=st.get(R(2))
                st.setx(R(0), None)  # runtime-dependent
                st.r['__csel__'] = (R(0), a, b, ins.op_str.split(',')[-1].strip())
            elif m == 'cmp':
                a=st.get(R(0)); b=IMM(1) if ops[1].type==ARM64_OP_IMM else st.get(R(1))
                st.flags=(a,b)
            elif m in ('str','stur'):
                # store to [sp, #off] ?
                mem=ops[1] if ops[1].type==ARM64_OP_MEM else None
                if mem and ins.reg_name(mem.mem.base)=='sp':
                    st.stk[mem.mem.disp]=st.get(R(0))
            elif m in ('ldr','ldur'):
                mem=ops[1] if ops[1].type==ARM64_OP_MEM else None
                if mem and ins.reg_name(mem.mem.base)=='sp':
                    st.setx(R(0), st.stk.get(mem.mem.disp, None))
                else:
                    st.setx(R(0), None)  # data load -> unknown
            elif m in ('stp',):
                mem=ops[2] if len(ops)>2 and ops[2].type==ARM64_OP_MEM else None
                if mem and ins.reg_name(mem.mem.base)=='sp':
                    st.stk[mem.mem.disp]=st.get(R(0)); st.stk[mem.mem.disp+8]=st.get(R(1))
            elif m in ('ldp',):
                mem=ops[2] if len(ops)>2 and ops[2].type==ARM64_OP_MEM else None
                if mem and ins.reg_name(mem.mem.base)=='sp':
                    st.setx(R(0), st.stk.get(mem.mem.disp)); st.setx(R(1), st.stk.get(mem.mem.disp+8))
                else:
                    st.setx(R(0), None); st.setx(R(1), None)
            elif m in ('nop','hint'): pass
            else:
                # unknown insn: invalidate dest if it has one reg operand
                if ops and ops[0].type==ARM64_OP_REG: st.setx(R(0), None)
        except Exception:
            if ops and ops[0].type==ARM64_OP_REG:
                try: st.setx(R(0), None)
                except: pass
    return (va + len(ins_list)*4, [], 'falloff', 'ran off block')

def build_cfg(entry_off, max_blocks=4000):
    cfg = {}; seen = set(); stack = [entry_off]
    while stack and len(cfg) < max_blocks:
        b = stack.pop()
        if b in seen: continue
        seen.add(b)
        term_va, succs, mnem, note = emulate_block(b)
        succ_offs = [s - BASE for s in succs if s and 0 <= (s-BASE) < len(DATA)]
        cfg[b] = {'term': term_va-BASE, 'succ': succ_offs, 'mnem': mnem, 'note': note}
        for s in succ_offs:
            if s not in seen: stack.append(s)
    return cfg

# real (non-opaque-predicate) instructions in a block: loads/stores/calls/alu that touch non-sp-scratch
def real_insns(start_off, term_off):
    out = []
    for ins in md.disasm(DATA[start_off:term_off+4], BASE+start_off):
        o = ins.address - BASE
        m = ins.mnemonic
        # skip the opaque-predicate scaffolding (sp-scratch store/load of consts, adrp/movk chains, and/eor/madd on scratch)
        if m in ('bl','blr'):
            out.append((o, m, ins.op_str, 'CALL'))
        elif m in ('ldr','ldp','ldur','ldrb','ldrh') and '[' in ins.op_str and 'sp,' not in ins.op_str:
            out.append((o, m, ins.op_str, 'LOAD'))
        elif m in ('str','stp','stur','strb','strh') and '[' in ins.op_str and 'sp,' not in ins.op_str:
            out.append((o, m, ins.op_str, 'STORE'))
        if o >= term_off: break
    return out

def dis_range(start_off, end_off):
    for ins in md.disasm(DATA[start_off:end_off], BASE+start_off):
        o = ins.address - BASE
        print('  0x%06x  %-8s %s' % (o, ins.mnemonic, ins.op_str))

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'block'
    if cmd == 'dis':
        s = int(sys.argv[2], 16); e = int(sys.argv[3], 16) if len(sys.argv) > 3 else s + 0x100
        dis_range(s, e)
    elif cmd == 'block':
        start = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xa03c8
        r = emulate_block(start)
        print('block 0x%x -> @0x%x (%s): %s'%(start, r[0]-BASE, r[2], r[3]))
        print('successors:', ['0x%x'%(s-BASE) for s in r[1]])
    elif cmd == 'char':
        # characterize a function: CFG via deobfuscator, count ARX-density / 16B writes / calls
        entry = int(sys.argv[2], 16)
        cfg = build_cfg(entry, max_blocks=600)
        arx = {'eor':0,'and':0,'orr':0,'ror':0,'extr':0,'add':0,'sub':0,'lsl':0,'lsr':0,'mul':0,'madd':0}
        w16 = []  # stp / consecutive str (16-byte writes)
        calls = set(); loads = 0; stores = 0
        seedgen = BASE + 0x10ac2c
        seen = set()
        for b in sorted(cfg):
            for ins in md.disasm(DATA[b:cfg[b]['term']+4], BASE+b):
                o = ins.address - BASE
                if o in seen: continue
                seen.add(o)
                m = ins.mnemonic
                if m in arx: arx[m]+=1
                if m == 'stp' and '[' in ins.op_str and 'sp' not in ins.op_str.split('[')[1][:4]:
                    w16.append(o)
                if m in ('str','strb','strh') and '[' in ins.op_str: stores+=1
                if m in ('ldr','ldrb','ldrh','ldp') and '[' in ins.op_str: loads+=1
                if m == 'bl':
                    t = ins.operands[0].imm if ins.operands and ins.operands[0].type==ARM64_OP_IMM else None
                    if t: calls.add(t-BASE)
                if o >= cfg[b]['term']: break
        arxtot = sum(arx.values())
        print('fn 0x%x: %d blocks, ARX=%d %s'%(entry, len(cfg), arxtot, {k:v for k,v in arx.items() if v}))
        print('  16B-stp writes: %d %s'%(len(w16), ['0x%x'%x for x in w16[:8]]))
        print('  loads=%d stores=%d  calls=%s'%(loads, stores, sorted('0x%x'%c for c in calls)[:12]))
        if seedgen-BASE in calls or any(cfg[b]['note'].find('10ac2c')>=0 for b in cfg):
            print('  *** references seed-gen 0x10ac2c ***')
    elif cmd == 'cfg':
        entry = int(sys.argv[2], 16)
        cfg = build_cfg(entry)
        print('CFG from 0x%x: %d blocks'%(entry, len(cfg)))
        unres = [b for b in cfg if cfg[b]['mnem']=='br' and 'UNRESOLVED' in cfg[b]['note']]
        print('unresolved br:', len(unres), ['0x%x'%b for b in unres[:8]])
        calls = set()
        for b in sorted(cfg):
            for o,m,ops,tag in real_insns(b, cfg[b]['term']):
                if tag=='CALL' and ('#0x' in ops):
                    try: calls.add(int(ops.split('#')[1],16)-BASE)
                    except: pass
        print('distinct CALL targets:', sorted('0x%x'%c for c in calls)[:20])
        # flag calls to memcpy 0x172a50
        if 0x172a50 in calls: print('  -> reaches memcpy 0x172a50 (slot16 copy)')
