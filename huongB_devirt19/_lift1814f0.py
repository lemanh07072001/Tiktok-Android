#!/usr/bin/env python3
# Static lift of VM report-builder program 0x1814f0 (libmetasec_ov.so).
# Bytecode is PLAINTEXT in file; operand ^= 0x6a9091b9. Goal: map branch/callout structure
# to locate the pskVersion gate that decides emit-#18/#19 (772) vs skip (408).
import struct, importlib.util, sys
spec=importlib.util.spec_from_file_location("d","_vm_static_decode.py"); d=importlib.util.module_from_spec(spec)
sys.argv=['x','bin/libmetasec_ov.so']; spec.loader.exec_module(d)
data=open('bin/libmetasec_ov.so','rb').read()
XOR=0x6a9091b9
_,handlers,trap=d.decode_context(0x52924)
valid=set(handlers.keys())

# section ranges (module-relative, load base 0)
def in_text(a):   return 0x1000 <= a < 0x17bbf0        # .text before bytecode blob
def in_bc(a):     return 0x17bbf0 <= a < 0x196000      # bytecode blob (branch targets land here)
def in_rodata(a): return 0x196000 <= a < 0x1f0000      # rodata-ish
def classify(v):
    if v < 0x40:               return f"imm/reg#{v}"
    if in_text(v):             return f".text 0x{v:x}"
    if in_bc(v):               return f"BC+0x{v-0x1814f0:x} (@0x{v:x})"
    if in_rodata(v):           return f".rodata 0x{v:x}"
    return f"0x{v:x}"

PROG=0x1814f0; END=0x184780
n=(END-PROG)//8
print(f"prog 0x{PROG:x}  ({n} entries max, until next prog 0x{END:x})")
print(f"valid opcodes: {sorted(valid)}\n")

op44=[]; callouts=[]; op18=[]; last_valid=0
for k in range(n):
    off=PROG+k*8
    w=struct.unpack_from('<I',data,off)[0]; opnd=struct.unpack_from('<I',data,off+4)[0]
    op=w&0x3f; dec=opnd^XOR
    hi=w>>6  # upper bits of opcode word (reg fields / flags)
    if op in valid: last_valid=k
    if op==44: op44.append((k,off,w,dec))
    if op==18: op18.append((k,off,dec))
    # a "callout" heuristic: operand decodes into .text (a native fn addr)
    if in_text(dec): callouts.append((k,off,op,dec))

print(f"=== op44 (computed-branch) count={len(op44)} ===")
for k,off,w,dec in op44[:40]:
    print(f"  [{k:4d}] @0x{off:x} word=0x{w:08x} target/operand_dec={classify(dec)}")
print(f"\n=== operands that are .text addresses (native call-outs) count={len(callouts)} ===")
for k,off,op,dec in callouts[:40]:
    print(f"  [{k:4d}] @0x{off:x} op{op} -> {classify(dec)}")
print(f"\nlast entry with a valid opcode: idx {last_valid} (offset 0x{PROG+last_valid*8:x}); "
      f"=> program likely ends near here")
