#!/usr/bin/env python3
# _sign_symex.py — angr symbolic execution of the sign VM (0x11a1e0 / body 0x11a390)
# in libmetasec_ov.so, to find the gate condition that makes it bail at 0x11a270 vs
# proceed to real work. Uninitialized globals are symbolic; we watch the branch guards
# and which memory (globals / init-state) the bail depends on.
import angr, claripy, logging, sys
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)

SO = "bin/libmetasec_ov.so"
proj = angr.Project(SO, auto_load_libs=False, main_opts={'base_addr': 0x0})
B = proj.loader.main_object.mapped_base   # 0 given base_addr=0
def A(x): return B + x
print("loaded; base=%#x entry-VM=%#x" % (B, A(0x11a1e0)))

BAIL = A(0x11a270)      # the early-return we want to AVOID
SETREAD = A(0x117e94)   # value-GET (real-work signal) — reaching it = progress

# Start at the VM body 0x11a390 (0x11a1e0 is a thin wrapper). Symbolic args.
st = proj.factory.blank_state(addr=A(0x11a390),
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                     angr.options.LAZY_SOLVES})
# a sane stack
st.regs.sp = 0x7ffff000
st.regs.x29 = 0x7ffff000
# args (post-0x11a1e0 shift): x0=a(cmd), x1=b, x2=c(long), x3=d(jstr), x4=e(obj)
st.regs.x0 = claripy.BVV(1, 64)
for r in (1,2,3,4): setattr(st.regs, "x%d"%r, claripy.BVS("arg%d"%r, 64))

simgr = proj.factory.simulation_manager(st)

# explore a bounded number of steps; record branch guards that mention memory reads
guards=[]
def step_watch(sm):
    for s in sm.active:
        # record the most recent guard if it is symbolic (data-dependent)
        pass
    return sm

STEPS=int(sys.argv[1]) if len(sys.argv)>1 else 400
reached_bail=False; reached_setread=False
seen=set()
for i in range(STEPS):
    if not simgr.active: break
    simgr.step()
    for s in list(simgr.active):
        pc = s.addr - B
        if pc not in seen and pc < 0x200000:
            seen.add(pc)
        if s.addr == BAIL: reached_bail=True
        if s.addr == SETREAD: reached_setread=True
    # cap state explosion
    if len(simgr.active) > 40:
        simgr.active[:] = simgr.active[:40]
print("steps done; distinct in-range PCs visited=%d bail=%s setread=%s" % (len(seen), reached_bail, reached_setread))
# show the guard constraints on any state that reached bail
for s in simgr.active[:3]:
    print("state pc=%#x constraints=%d" % (s.addr-B, len(s.solver.constraints)))
print("sample visited (sorted):", sorted(hex(x) for x in list(seen))[:40])
