import angr, claripy, logging, sys
for n in ('angr','cle','pyvex','claripy'): logging.getLogger(n).setLevel(logging.ERROR)
SO="bin/libmetasec_ov.so"
proj=angr.Project(SO, auto_load_libs=False, main_opts={'base_addr':0x0})
START=int(sys.argv[1],16) if len(sys.argv)>1 else 0x9ecc0
STEPS=int(sys.argv[2]) if len(sys.argv)>2 else 600
# real-work signal addresses
SIGNALS={0x117e94:"settings-GET",0x1591bc:"AES-keysched",0x9fdac:"SM3",0x10bbd0:"crypt-RC4",
         0x10c158:"crypt-AES",0x9ecc0:"sign",0x11a1e0:"MS.b",0x6bb84:"mssdk-accessor",
         0x117e14:"store-loader",0x1185d0:"devsec-getter"}
st=proj.factory.blank_state(addr=START,
    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                 angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                 angr.options.LAZY_SOLVES,
                 angr.options.CALLLESS if hasattr(angr.options,'CALLLESS') else angr.options.LAZY_SOLVES})
st.regs.sp=0x7ffff000; st.regs.x29=0x7ffff000
for r in range(0,8): setattr(st.regs,"x%d"%r, claripy.BVS("x%d"%r,64))
simgr=proj.factory.simulation_manager(st)
seen=set(); hits={}
for i in range(STEPS):
    if not simgr.active: break
    try: simgr.step()
    except Exception as e: break
    for s in list(simgr.active):
        pc=s.addr
        if pc<0x200000: seen.add(pc)
        if pc in SIGNALS and SIGNALS[pc] not in hits: hits[SIGNALS[pc]]=i
    if len(simgr.active)>60: simgr.active[:]=simgr.active[:60]
print("START=%#x steps=%d distinct-PCs=%d"%(START,STEPS,len(seen)))
print("REAL-WORK signals reached:", hits if hits else "NONE")
# print call targets (functions reached below START region = real work)
lows=sorted(x for x in seen if x<START-0x1000 or x>START+0x2000)
print("out-of-region PCs (calls into other funcs):", [hex(x) for x in lows[:30]])
