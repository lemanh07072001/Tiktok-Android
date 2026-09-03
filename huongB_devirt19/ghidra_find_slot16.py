# Ghidra headless postScript — khoanh vùng slot16 producer.
# Chạy:
#   $GHIDRA/support/analyzeHeadless <projDir> tt \
#     -import huongB_devirt19/bin/libmetasec_ov.so \
#     -postScript ghidra_find_slot16.py \
#     -scriptPath huongB_devirt19
# Mục tiêu: unhex decoder @0x891f4 có 5 caller; hàm nào build hex slot16 (32 char)
# thì nó chính là producer. Script decompile 5 ứng viên + dump C + xref graph.
#@category TikTok
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os

# offset file (= vaddr) -> địa chỉ Ghidra (imageBase + offset)
BASE = currentProgram.getImageBase()
def A(off):
    return BASE.add(off)

UNHEX      = 0x891f4
CANDIDATES = [0x887e0, 0xcaa0c, 0x119108, 0x1349ac, 0x13ab30]
SM3_DRV    = 0x9fdac   # consumer slot16 (SM3 driver) — để nhận diện path đúng
OUTDIR     = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), "_ghidra_out")
try: os.makedirs(OUTDIR)
except: pass

fm  = currentProgram.getFunctionManager()
dec = DecompInterface(); dec.openProgram(currentProgram)
mon = ConsoleTaskMonitor()

def fn_at(off):
    f = fm.getFunctionContaining(A(off))
    return f

def decompile(f):
    r = dec.decompileFunction(f, 120, mon)
    if r and r.decompileCompleted():
        return r.getDecompiledFunction().getC()
    return "// decompile FAILED"

def callers_of(off):
    out = []
    for ref in getReferencesTo(A(off)):
        if ref.getReferenceType().isCall():
            fc = fm.getFunctionContaining(ref.getFromAddress())
            out.append((ref.getFromAddress(), fc.getEntryPoint() if fc else None))
    return out

print("=== image base = %s ===" % BASE)
print("=== callers of UNHEX 0x%x ===" % UNHEX)
for site, ent in callers_of(UNHEX):
    print("  call@%s  in fn %s" % (site, ent))

# decompile 5 ứng viên -> file, và tìm dấu hiệu producer:
#   heuristic: hàm producer sẽ (a) gọi 1 hàm hash/SM3 trước khi build hex,
#              (b) tạo std::string rồi feed vào unhex,
#              (c) nằm trên path tới SM3_DRV consumer.
sm3_fn = fn_at(SM3_DRV)
sm3_ep = sm3_fn.getEntryPoint() if sm3_fn else None
print("\n=== SM3 driver (consumer) fn = %s ===" % sm3_ep)

report = []
for off in CANDIDATES:
    f = fn_at(off)
    if not f:
        print("  0x%x: NO FUNCTION" % off); continue
    c = decompile(f)
    fp = os.path.join(OUTDIR, "fn_%x.c" % off)
    with open(fp, "w") as fh: fh.write(c)
    # đếm callee là hash-ish + độ dài
    ncalls = c.count("(")
    hashish = sum(c.lower().count(k) for k in ("sha","sm3","md5","digest","hex"))
    feeds_unhex = ("0x%x" % UNHEX) in c or "FUN_%08x" % (BASE.getOffset()+UNHEX) in c
    report.append((off, len(c), hashish, str(f.getName())))
    print("  0x%x -> %s  (C %dB, hash-hint=%d) dumped %s" %
          (off, f.getName(), len(c), hashish, fp))

print("\n=== RANK (nhiều hash-hint = khả năng producer cao) ===")
for off, sz, hh, nm in sorted(report, key=lambda r: -r[2]):
    print("  0x%x  hash-hint=%d  %s" % (off, hh, nm))
print("\nĐọc _ghidra_out/fn_*.c: tìm hàm build chuỗi 32 hex feed vào unhex = producer.")
dec.dispose()
