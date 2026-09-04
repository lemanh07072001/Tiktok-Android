package tt;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.*;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.UnHook;
import java.io.File;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Dump {
    static long tick = 0;
    static Emulator<?> emu0;
    static boolean[] signPhaseRef = {false};
    static VM theVM;
    static final File STORE_DIR = new File(System.getProperty("STORE_DIR","state/phone_sync/.msdata/mssdk/ov"));
    static final File FILES_MIRROR = new File(System.getProperty("FILES_MIRROR","state/phone_files/files"));
    public static void main(String[] args) throws Exception {
        Properties got = new Properties();
        got.load(Dump.class.getResourceAsStream("/got_symbols.properties"));
        AndroidEmulator emu = AndroidEmulatorBuilder.for64Bit().setProcessName("com.zhiliaoapp.musically").build();
        emu0 = emu;
        Memory memory = emu.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        emu.getSyscallHandler().addIOResolver(new IOResolver() {
            public FileResult resolve(Emulator e, String path, int oflags) {
                if (signPhaseRef[0] && (path.contains("keva")||path.contains("seed")||path.contains(".msdata")||path.contains("mssdk"))) System.out.println("[OPEN] "+path);
                String bn = path; int sl = path.lastIndexOf('/'); if (sl>=0) bn=path.substring(sl+1);
                // device-secret store files (by basename)
                if (bn.startsWith(".msp_")||bn.startsWith(".mss_")||bn.startsWith(".msf3_")||bn.startsWith(".msfs_")) {
                    File real = new File(STORE_DIR, bn);
                    if (real.exists()) return FileResult.success(new com.github.unidbg.linux.file.SimpleFileIO(oflags, real, path));
                }
                // keva device-state blob (d8b674...) — full genuine x-argus needs it
                if (bn.startsWith("d8b674")) {
                    File real = new File(FILES_MIRROR, "keva/repo/d8b674543fc0b023b69f6a3f5a0f287d458ea204/"+bn);
                    if (real.isFile()) { System.out.println("[FILE] SERVE keva "+bn);
                        return FileResult.success(new com.github.unidbg.linux.file.SimpleFileIO(oflags, real, path)); }
                }
                return null;
            }
        });
        VM vm = emu.createDalvikVM(); theVM = vm;
        vm.setVerbose(false);
        vm.setJni(new AbstractJni() {
            public void callVoidMethodV(BaseVM v, DvmObject<?> o, String sig, VaList va){
                if (sig.contains("release")||sig.contains("close")) { System.out.println("   [MediaDrm.release no-op]"); return; }
                System.out.println("   [callVoid unhandled] "+sig); }
            public DvmObject<?> getStaticObjectField(BaseVM v, DvmClass c, String sig){
                if (sig.contains("PROPERTY_DEVICE_UNIQUE_ID")) { System.out.println("   [MediaDrm.PROPERTY_DEVICE_UNIQUE_ID]"); return new StringObject(theVM,"deviceUniqueId"); }
                System.out.println("   [getStaticObjectField unhandled] "+sig);
                return super.getStaticObjectField(v,c,sig); }
            public DvmObject<?> newObjectV(BaseVM v, DvmClass c, String sig, VaList va){
                if (sig.contains("java/util/UUID") && sig.contains("(JJ)V")) {
                    long hi=0,lo=0; try{ hi=va.getLongArg(0); lo=va.getLongArg(1);}catch(Throwable t){}
                    System.out.println("   [UUID new] "+Long.toHexString(hi)+"-"+Long.toHexString(lo));
                    return c.newObject(new long[]{hi,lo});
                }
                if (sig.contains("android/media/MediaDrm")) {
                    System.out.println("   [MediaDrm new] "+sig);
                    return c.newObject("MediaDrm");
                }
                System.out.println("   [newObject unhandled] "+sig);
                return c.newObject(null); }
            public DvmObject<?> callObjectMethodV(BaseVM v, DvmObject<?> o, String sig, VaList va){
                if (sig.startsWith("b(")) { return null; }
                if (sig.contains("getPropertyByteArray")) {
                    String duid = System.getenv("MSB_DUID"); if(duid==null||duid.isEmpty()) duid="sZLyIifaxWeiNVYmORvBTisngBeWLDE ";
                    System.out.println("   [MediaDrm.getPropertyByteArray] -> "+duid+" ("+duid.length()+"B)");
                    return new ByteArray(theVM, duid.getBytes(StandardCharsets.UTF_8));
                }
                if (sig.contains("getBytes")) {
                    Object val = (o==null?null:o.getValue()); String str = val==null?"":val.toString();
                    System.out.println("   [getBytes impl] sig="+sig+" str="+str.substring(0,Math.min(30,str.length())));
                    return new ByteArray(theVM, str.getBytes(StandardCharsets.UTF_8));
                }
                System.out.println("   [callObj unhandled] "+sig);
                return null; }
            public DvmObject<?> callStaticObjectMethodV(BaseVM v, DvmClass c, String sig, VaList va){
                if (sig.contains("->b(") || sig.startsWith("b(")) {
                    int cmd=0; try { cmd=va.getIntArg(0); } catch(Throwable t){}
                    Object ret = msbCallback(cmd);
                    System.out.println("   [MS.b cb] cmd=0x"+Integer.toHexString(cmd)+" -> "+(ret==null?"NULL(need impl)":ret));
                    return ret==null?null:new StringObject(theVM, ret.toString());
                }
                if (sig.contains("valueOf")) {
                    int iv=0; try { iv=va.getIntArg(0); } catch(Throwable t){}
                    DvmObject<?> boxed = theVM.resolveClass("java/lang/Integer").newObject(iv);
                    System.out.println("   [valueOf impl] "+iv+" -> "+(boxed==null?"null":"Integer"));
                    return boxed;
                }
                if (!sig.contains("->b(")) System.out.println("   [callStatic unhandled] "+sig);
                return null; }
        });
        DvmClass object = vm.resolveClass("java/lang/Object");
        vm.resolveClass("com/bytedance/mobsec/metasec/ov/MS", object);
        DalvikModule dmod = vm.loadLibrary(new File("native/libmetasec_ov.so"), true);
        Module mod = dmod.getModule(); long base = mod.base;
        SvcMemory svc = emu.getSvcMemory();
        List<Module> mods = new ArrayList<>(memory.getLoadedModules());
        for (String k : got.stringPropertyNames()) {
            long gotOff = Long.parseLong(k,16); long val = readLong(emu, base+gotOff);
            boolean res=false; for (Module m:mods) if (val>=m.base && val<m.base+m.size){res=true;break;}
            if (res) continue; final String sym = got.getProperty(k);
            UnidbgPointer stub = svc.registerSvc(new Arm64Svc(){ public long handle(Emulator<?> e){
                if (signPhaseRef[0]) System.out.println("   [STUB called in sign] "+sym);
                if (sym.contains("try_lock")) return 1;
                if (sym.contains("clock")&&sym.contains("now")) return (tick+=1_000_000); return 0; }});
            writeLong(emu, base+gotOff, stub.peer);
        }
        // ---- TIME LOCK (byte-exact): force gettimeofday/clock_gettime/time to FIXTIME ----
        final long FIXTIME = Long.getLong("FIXTIME", 0L);
        if (FIXTIME > 0) {
          long[][] tf = {{0x1eedf8,0},{0x1eeeb0,1},{0x1ef1f8,2}}; // {gotoff, kind: 0=gettimeofday,1=clock_gettime,2=time}
          for (long[] e : tf) {
            final int kind=(int)e[1];
            UnidbgPointer stub = svc.registerSvc(new Arm64Svc(){ public long handle(Emulator<?> ee){
              com.github.unidbg.arm.backend.Backend b=ee.getBackend();
              if (kind==0){ long tv=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue(); if(tv!=0){ wl(ee,tv,FIXTIME); wl(ee,tv+8,0);} return 0; }
              if (kind==1){ long tp=b.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue(); if(tp!=0){ wl(ee,tp,FIXTIME); wl(ee,tp+8,0);} return 0; }
              long t=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue(); if(t!=0) wl(ee,t,FIXTIME); return FIXTIME;
            }});
            writeLong(emu, base+e[0], stub.peer);
          }
          System.out.println("[TIME LOCK] FIXTIME="+FIXTIME);
        }
        Debugger dbg = emu.attach();
        dbg.addBreakPoint(mod, 0x119ba0, (e,a) -> { e.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0,0L);
            e.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, base+0x119ba4); return true; });
        dbg.addBreakPoint(mod, 0xb0d10, (e,a) -> {
            long x1=e.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
            System.out.println("[READER 0xb0d10] key="+readCpp(e,x1)); return false; });
        // Phase 3 (Mac fresh-RE): anchor pipeline at AES-CBC 0x159d70; capture report via magic scan
        final long CB=base;
        final int[] aesHits={0};
        final long[] aesInBuf={0};
        emu.getBackend().hook_add_new(new CodeHook(){
            public void hook(Backend b,long a,int sz,Object u){
                if(!signPhaseRef[0]) return;
                aesHits[0]++;
                if(aesHits[0]==1){ long x0=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                    long x1=b.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                    System.out.printf("   [AES-CBC 0x159d70 hit#1] x0=0x%x x1=0x%x%n", x0, x1);
                    byte[] magic={0x08,(byte)0xd2,(byte)0xa4,(byte)0x80,(byte)0x82,0x04};
                    int found=0;
                    for(long sb=0x12000000L; sb<0x12800000L && found<3; sb+=0x1000){
                        try{ byte[] pg=b.mem_read(sb,0x1000);
                            for(int i=0;i<pg.length-6;i++){ boolean m=true; for(int k=0;k<6;k++) if(pg[i+k]!=magic[k]){m=false;break;}
                                if(m){ found++; byte[] rpt=b.mem_read(sb+i,Math.min(700,0x1000-i));
                                    java.nio.file.Files.write(new File("/tmp/rpt"+found+".bin").toPath(),rpt);
                                    StringBuilder hx=new StringBuilder(); for(int j=0;j<32;j++) hx.append(String.format("%02x",rpt[j]&0xff));
                                    System.out.printf("   [REPORT @0x%x] %s (/tmp/rpt%d.bin)%n",sb+i,hx,found);} }
                        }catch(Throwable t){}
                    }
                    System.out.println("   [magic scan at AES-time: found="+found+"]"); }
            }
            public void onAttach(UnHook un){} public void detach(){}
        }, base+0x159d70, base+0x159d71, null);
        dmod.callJNI_OnLoad(emu);
        System.out.println("[OK] JNI_OnLoad done -> call device-secret getter 0x1185d0");
        long[] outbuf = { emu.getMemory().malloc(24, true).getPointer().peer };
        final boolean[] signPhase = signPhaseRef;
        emu.getBackend().hook_add_new(new CodeHook(){
            public void hook(Backend b,long a,int sz,Object u){
                long x1=b.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                if (signPhase[0]) { String k=readCpp(emu0,x1); if(k!=null&&k.length()>0&&!k.equals("?")) System.out.println("   [store GET] key="+k); }
                else b.reg_write(Arm64Const.UC_ARM64_REG_X8, outbuf[0]);
            }
            public void onAttach(UnHook un){} public void detach(){}
        }, mod.base+0x117e94, mod.base+0x117e95, null);
        try {
            Number r = mod.callFunction(emu, 0x1185d0L);
            long store = r.longValue();
            System.out.printf("[*] 0x1185d0 -> store=0x%x%n", store);
            String[] keys = {"kiid"};
            for (String key : keys) {
                UnidbgPointer kp = mkCpp(emu.getMemory(), key);
                e2(emu, outbuf[0]);   // clear out
                mod.callFunction(emu, 0x117e94L, store, kp.peer);
                System.out.println("   ["+key+"] = " + readCpp(emu, outbuf[0]));
            }
            // (mssdk_setting accessor 0x6bb84 needs the real SDK ctx — skipped; see sign trace below)
            dbg.addBreakPoint(mod, 0x118e54, (e,a) -> {
                if (signPhase[0]) { long x1=e.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                    System.out.println("   [SIGN GET 0x118e54] key="+readCpp(e,x1)); } return true; });
        } catch (Throwable t){ System.out.println("[STOP] "+t); t.printStackTrace(); }
        // ---- SIGN dispatch 0x11a1e0 trace: find the bail PC (uniform 2356-instr early return) ----
        try {
            final long[] lastpc = {0}; final long[] cnt = {0};
            final java.util.List<String> calls = new java.util.ArrayList<>();
            emu.getBackend().hook_add_new(new CodeHook(){
                public void hook(Backend b,long a,int sz,Object u){ lastpc[0]=a; cnt[0]++;
                    try { byte[] ib=b.mem_read(a,4); int insn=(ib[0]&0xff)|((ib[1]&0xff)<<8)|((ib[2]&0xff)<<16)|((ib[3]&0xff)<<24);
                        if ((insn&0xfc000000)==0x94000000){ int off=insn&0x03ffffff; if((off&(1<<25))!=0) off-=(1<<26);
                            long tgt=(a+((long)off*4))-mod.base; if(calls.size()<80) calls.add(String.format("bl 0x%x",tgt)); }
                        else if ((insn&0xfffffc1f)==0xd63f0000){ long tgt=b.reg_read(Arm64Const.UC_ARM64_REG_X0+((insn>>5)&0x1f)).longValue()-mod.base; if(calls.size()<200) calls.add(String.format("blr->0x%x",tgt&0xffffff)); }
                        else if ((insn&0xfffffc1f)==0xd61f0000){ long tgt=b.reg_read(Arm64Const.UC_ARM64_REG_X0+((insn>>5)&0x1f)).longValue()-mod.base; if(calls.size()<200) calls.add(String.format("br->0x%x",tgt&0xffffff)); }
                        else if (insn==0xd4000001){ long nr=b.reg_read(Arm64Const.UC_ARM64_REG_X8).longValue(); if(calls.size()<200) calls.add("svc nr="+nr); }
                    } catch(Throwable t){}
                }
                public void onAttach(UnHook un){} public void detach(){}
            }, mod.base+0x11a1e0, mod.base+0x200000, null);
            com.sun.jna.Pointer env = vm.getJNIEnv();
            long msJ = vm.addLocalObject(vm.resolveClass("com/bytedance/mobsec/metasec/ov/MS"));
            long jurl = vm.addLocalObject(new StringObject(vm, "https://api16-normal-c-alisg.tiktokv.com/aweme/v2/feed/"));
            UnidbgPointer envP = UnidbgPointer.pointer(emu, ((UnidbgPointer)env).peer);
            signPhase[0]=true;
            // ★ report-struct probe: rptSelf captured at 0x95a3c; struct dump/inject at first 0x154f7c write (members live)
            final long BASE2=base; final int[] serHits={0}; final long[] rptSelf={0}; final boolean[] didDump={false};
            final long OFF24 = Long.decode(System.getProperty("OFF24","-1"));
            if (System.getenv("MSB_RPT")!=null) {
              emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                if(rptSelf[0]==0){ rptSelf[0]=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                  System.out.printf("   [RPT] 0x95a3c self=0x%x%n", rptSelf[0]); } }
                public void onAttach(UnHook un){} public void detach(){} }, base+0x95a3c, base+0x95a3d, null);
              // window trace: between #23 emit (rpt+0x71 len21) and #25 emit (rpt+0x77) → #24 built+skipped here
              final boolean[] inWin={false}; final java.util.LinkedHashMap<Long,String> reads=new java.util.LinkedHashMap<>();
              emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                if(rptSelf[0]==0) return;
                long dst=b.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue(); long doff=dst-0x12555000L;
                long len=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                if(doff==0x71 && len==21 && !inWin[0]){ inWin[0]=true; System.out.println("   [WIN] #23 emitted @rpt+0x71 -> tracing #24-build reads..."); }
                else if(doff==0x77 && inWin[0]){ inWin[0]=false;
                  System.out.println("   [WIN] #25 @rpt+0x77 -> window closed. Reads of device-state/heap std::strings in window:");
                  for(java.util.Map.Entry<Long,String> e:reads.entrySet()) System.out.printf("     read 0x%x : %s%n", e.getKey(), e.getValue());
                } }
                public void onAttach(UnHook un){} public void detach(){} }, base+0x154f7c, base+0x154f80, null);
              // ReadHook (broad): during window, record reads whose 8-byte value looks like a std::string control (find #24 value slot)
              emu.getBackend().hook_add_new(new ReadHook(){ public void hook(Backend b,long addr,int size,Object u){
                if(!inWin[0]||size!=8||reads.size()>400 || reads.containsKey(addr)) return;
                try{ byte[] c=b.mem_read(addr,24); long cap=readLE(c,0),ln=readLE(c,8),ptr=readLE(c,16);
                  String v=null;
                  // long-mode std::string: cap odd, small len, valid ptr → print content
                  if((cap&1)!=0 && ln>0 && ln<=48 && ptr>0x1000){ try{ String s=new String(b.mem_read(ptr,(int)Math.min(ln,44))); boolean pr=true; for(char ch:s.toCharArray()) if(ch<9||ch>126){pr=false;break;} if(pr) v="str["+ln+"]='"+s+"'"; }catch(Throwable t){} }
                  // empty long-mode string (cap even w/ len0 ptr0) adjacent candidate
                  if(v!=null) reads.put(addr, v);
                }catch(Throwable t){} }
                public void onAttach(UnHook un){} public void detach(){} }, BASE2+0x1000, 0x800000000L, null);
            }
            // ★ AES probe: dump AES-CBC 0x159d70 args (input buffer + length) → for buffer-append injection
            if (System.getenv("MSB_AESPROBE")!=null) {
              final int[] ah={0};
              emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                if(!signPhase[0]||ah[0]>=3) return; ah[0]++;
                long x0=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                long x1=b.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                long x2=b.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                long x3=b.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
                System.out.printf("[AESPROBE #%d] x0=0x%x x1=0x%x x2=0x%x x3=0x%x%n", ah[0], x0,x1,x2,x3);
                for(long p : new long[]{x0,x1}){ try{ byte[] d=b.mem_read(p,48); StringBuilder h=new StringBuilder(); for(byte bb:d) h.append(String.format("%02x",bb&0xff));
                  System.out.printf("   [buf 0x%x] %s%n", p, h.toString()); }catch(Throwable t){} } }
                public void onAttach(UnHook un){} public void detach(){} }, base+0x159d70, base+0x159d74, null);
              // copy-fn 0x1728b4(dst,src,len): log when src/dst = report buffer 0x12555000 → report length
              emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                if(!signPhase[0]) return;
                long x0=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                long x1=b.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                long x2=b.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                if((x0>=0x12555000L&&x0<0x12555400L)||(x1>=0x12555000L&&x1<0x12555400L))
                  System.out.printf("[COPY 0x1728b4] dst=0x%x src=0x%x len=%d%n", x0,x1,x2); }
                public void onAttach(UnHook un){} public void detach(){} }, base+0x1728b4, base+0x1728b8, null);
            }
            // ★ (a)/(b) test: who READS the report buffer 0x12555000 (is the sig a hash of the report?)
            if (System.getenv("MSB_RPTREAD")!=null) {
              final java.util.LinkedHashMap<Long,Integer> rdrs=new java.util.LinkedHashMap<>();
              final boolean[] emitted={false};
              emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                if(signPhase[0]){ long dst=b.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue(); if(dst-0x12555000L==0xa9) emitted[0]=true; } }
                public void onAttach(UnHook un){} public void detach(){} }, base+0x154f7c, base+0x154f80, null);
              emu.getBackend().hook_add_new(new ReadHook(){ public void hook(Backend b,long addr,int size,Object u){
                if(!signPhase[0]) return; long pc=0; try{ pc=b.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue()-BASE2; }catch(Throwable t){}
                rdrs.merge(pc,1,Integer::sum); }
                public void onAttach(UnHook un){} public void detach(){} }, 0x12555000L, 0x12555200L, null);
              Runtime.getRuntime().addShutdownHook(new Thread(){ public void run(){
                System.out.println("[RPTREAD] readers of report-buffer 0x12555000 (PC: count):");
                for(java.util.Map.Entry<Long,Integer> e:rdrs.entrySet()) System.out.printf("   PC 0x%x : %d reads%n", e.getKey(), e.getValue()); }});
            }
            // ★ VM tracer: log prog-0x1814f0 opcode stream (report-builder) + mark 0x154f7c emits → find #24 field-decision
            if (System.getenv("MSB_VMTRACE")!=null) {
              final java.util.List<String> tr=new java.util.ArrayList<>();
              final long inj24buf = emu.getMemory().malloc(0x80,false).getPointer().peer;  // persistent scratch (pre-allocated, safe)
              // mode8: inject #24 at the message-walker 0x154f24 ENTRY (before size-computation) so the buffer is sized WITH #24
              if("8".equals(System.getProperty("INJ24MODE")) && "1".equals(System.getProperty("INJ24"))){
                final int[] injc={0}; final long B3=base;
                emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                  if(!signPhase[0]) return;
                  long m=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                  // report message: [m+0]=descriptor with field-count matching the top report; #23 member @ +0xe0 non-null
                  try{ long d0=readLong(emu0,m); long nf=readLong(emu0,d0+0x30); long f23m=readLong(emu0,m+0xe0);
                    if(f23m==0 || nf<30 || nf>60) return;  // must be the top report message (30-60 fields, #23 built)
                    long charptr=readLong(emu0,B3+0x1fbe00+8); long slen=readLong(emu0,B3+0x1fbe00+4)&0xffffffffL;
                    b.mem_write(charptr+slen,new byte[]{0});
                    writeLong(emu0, m+0xe8, charptr);
                    injc[0]++;
                    if(injc[0]<=3) System.out.printf("[INJ24 mode8 #%d] @0x154f24 msg=0x%x nfields=%d #24 member=char* 0x%x%n", injc[0], m, nf, charptr);
                  }catch(Throwable t){} }
                  public void onAttach(UnHook un){} public void detach(){} }, base+0x154f24, base+0x154f28, null);
              }
              // field-writer 0x153fb0(x0=descriptor, x1=value-ptr, x2=dst): log field-tag + value-ptr + emptiness → identify #24 call
              emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                if(!signPhase[0]||tr.size()>4000) return;
                long x0=b.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                long x1=b.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                long x2=b.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                try{ int w9=(int)readLong(emu0,x0+8); int tag=w9<<3;   // tag = field<<3|wiretype
                  long valp=0, first=0; String pk="";
                  try{ valp=readLong(emu0,x1); if(valp!=0){ byte[] fb=b.mem_read(valp,8); first=fb[0]&0xff; pk="["+String.format("%02x%02x%02x%02x",fb[0]&0xff,fb[1]&0xff,fb[2]&0xff,fb[3]&0xff)+"]"; } }catch(Throwable t){}
                  tr.add(String.format("WR desc=0x%x f%d wt%d x1=0x%x *x1=0x%x %s", x0, (tag>>3)&0x1f, tag&7, x1, valp, pk));
                  int fnum=w9&0xff;   // raw field number
                  if(fnum==13){ // f13 = present bytes field ('d4aca5685605') — dump its member area raw to learn bytes encoding
                    StringBuilder h2=new StringBuilder(); try{ byte[] mm=b.mem_read(x1,32); for(byte bb:mm) h2.append(String.format("%02x",bb&0xff)); }catch(Throwable t){h2.append("ERR");}
                    tr.add(String.format("   [f13 member@0x%x raw32]=%s", x1, h2.toString()));
                    // follow *x1 as a possible ptr
                    try{ long mv=readLong(emu0,x1); StringBuilder h3=new StringBuilder(); byte[] pd=b.mem_read(mv,24); for(byte bb:pd) h3.append(String.format("%02x",bb&0xff));
                      tr.add(String.format("   [f13 *member=0x%x ->]=%s", mv, h3.toString())); }catch(Throwable t){} }
                  if((tag>>3&0x1f)==23 && "1".equals(System.getProperty("INJ24"))){
                    long msg=x1-0xe0;   // message base (x1 = &member = msg + desc.offset(f23)=0xe0); members are 8-byte ptrs
                    long mode=Long.decode(System.getProperty("INJ24MODE","0"));
                    if(mode==0) writeLong(emu0, msg+0xe8, BASE2+0x1fbe00);        // member = ptr to std::string [0x1fbe00]
                    else if(mode==2) writeLong(emu0, msg+0xe8, readLong(emu0,msg+0xe0));  // member = #23's submessage value (copy #23)
                    else if(mode==3){ // RECIPE A: deep-copy #23's sub-OBJECT to PRE-ALLOCATED persistent mem -> #24 = valid submessage
                      long obj23=readLong(emu0, msg+0xe0);        // #23 member value = sub-object ptr (obj23[0]=descriptor)
                      byte[] shell=b.mem_read(obj23, 0x40);
                      b.mem_write(inj24buf, shell);               // copy into pre-allocated scratch (no malloc in-hook)
                      writeLong(emu0, msg+0xe8, inj24buf);        // #24 member -> persistent copy
                      tr.add(String.format(">>> INJ24 mode3: #24 member=inj24buf 0x%x <- obj23 0x%x [0]=0x%x", inj24buf, obj23, readLong(emu0,obj23))); }
                    else if(mode==7){ // #24 = C-STRING (type 0x0e): member VALUE = char* to null-terminated string; writer does strlen
                      long charptr=readLong(emu0,BASE2+0x1fbe00+8);   // base64-DUID data ptr
                      long slen=readLong(emu0,BASE2+0x1fbe00+4)&0xffffffffL;   // len@+4 = 44
                      b.mem_write(charptr+slen, new byte[]{0});        // ensure null-terminated at end
                      byte[] chk=b.mem_read(charptr, (int)Math.min(slen+1,48));
                      writeLong(emu0, msg+0xe8, charptr);
                      tr.add(String.format(">>> INJ24 mode7: #24 member=char* 0x%x len=%d str=%s", charptr, slen, new String(chk).replaceAll("[^\\x20-\\x7e]","."))); }
                    else if(mode==6){ // #24 BYTES: member = inline {len@0, data@8} (like #13). data = base64-DUID bytes ptr
                      long strobj=BASE2+0x1fbe00;
                      long len=readLong(emu0,strobj+4)&0xffffffffL;   // SDK std::string len@+4 = 44
                      long dataptr=readLong(emu0,strobj+8);           // data ptr @+8
                      writeLong(emu0, msg+0xe8, len);                 // {len@0}
                      writeLong(emu0, msg+0xf0, dataptr);             // {data@8}
                      tr.add(String.format(">>> INJ24 mode6: #24={len=%d,data=0x%x} inline at msg+0xe8", len, dataptr)); }
                    else if(mode==5){ // DUMP #24 sub-schema: f24 descriptor +0x28 = sub-message descriptor
                      long fdesc24=x0+0x48; long subdesc=readLong(emu0,fdesc24+0x28);
                      long nsub=readLong(emu0,subdesc+0x30); long farray=readLong(emu0,subdesc+0x38);
                      tr.add(String.format(">>> #24 SUBSCHEMA: subdesc=0x%x nsub=%d farray=0x%x", subdesc, nsub, farray));
                      for(int i=0;i<Math.min(nsub,12);i++){ long fd=farray+(long)i*0x48;
                        long fnwt=readLong(emu0,fd+8), typ=readLong(emu0,fd+0x10), memoff=readLong(emu0,fd+0x18), subsub=readLong(emu0,fd+0x28);
                        tr.add(String.format("     subfield[%d]@0x%x: fnum=%d type=0x%x memoff=0x%x subdesc=0x%x", i, fd, (int)fnwt, typ, memoff, subsub)); } }
                    else { byte[] wv=b.mem_read(BASE2+0x1fbe00,24); b.mem_write(msg+0xe8, wv); }
                    tr.add(String.format(">>> INJ24(mode%d): msg+0xe8=0x%x set (member ptr -> 0x%x)", mode, msg+0xe8, BASE2+0x1fbe00)); }
                  if((tag>>3&0x1f)==23){ // on f23: dump regs → find struct_base (reg+0xe0 = #23 value); then #24 = base+0xe8
                    int[] regs={Arm64Const.UC_ARM64_REG_X3,Arm64Const.UC_ARM64_REG_X4,Arm64Const.UC_ARM64_REG_X19,Arm64Const.UC_ARM64_REG_X20,Arm64Const.UC_ARM64_REG_X21,Arm64Const.UC_ARM64_REG_X22,Arm64Const.UC_ARM64_REG_X23,Arm64Const.UC_ARM64_REG_X24,Arm64Const.UC_ARM64_REG_X25,Arm64Const.UC_ARM64_REG_X26,Arm64Const.UC_ARM64_REG_X27,Arm64Const.UC_ARM64_REG_X28};
                    String[] nm={"x3","x4","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28"};
                    for(int i=0;i<regs.length;i++){ long rv=b.reg_read(regs[i]).longValue();
                      // check if rv+0xe8 holds a std::string control (candidate struct_base)
                      String note="";
                      try{ byte[] c=b.mem_read(rv+0xe8,24); long cap=readLE(c,0),ln=readLE(c,8); note=String.format("[+0xe8]cap=0x%x ln=%d",cap,ln);
                        byte[] c2=b.mem_read(rv+0xe0,8); note+=String.format(" [+0xe0]=0x%x",readLE(c2,0)); }catch(Throwable t){}
                      tr.add(String.format("  REG %s=0x%x %s", nm[i], rv, note)); } } }
                catch(Throwable t){} }
                public void onAttach(UnHook un){} public void detach(){} }, base+0x153fb0, base+0x153fb4, null);
              // write trace at JVM exit
              Runtime.getRuntime().addShutdownHook(new Thread(){ public void run(){
                try{ StringBuilder sb=new StringBuilder(); for(String s:tr) sb.append(s).append("\n");
                  java.nio.file.Files.write(new File("/tmp/vmtrace.txt").toPath(), sb.toString().getBytes());
                  System.out.println("[VMTRACE] "+tr.size()+" lines -> /tmp/vmtrace.txt"); }catch(Throwable t){} }});
            }
            // INIT 0x4000001 with a config Object[] (notes/21: [aid,"","",token,sdkver,channel,...])
            DvmObject<?>[] cfg = {
                new StringObject(vm,"1233"), new StringObject(vm,""), new StringObject(vm,""),
                new StringObject(vm,""), new StringObject(vm,"45.7.3"), new StringObject(vm,"googleplay"),
                new StringObject(vm,"2024507030"), new StringObject(vm,"com.zhiliaoapp.musically")
            };
            long jcfg = vm.addLocalObject(new ArrayObject(cfg));
            cnt[0]=0; lastpc[0]=0; calls.clear();
            Number ri=null; try { ri=mod.callFunction(emu, 0x11a1e0L, envP.peer, msJ, 0x4000001L, 0L, 0L, 0L, jcfg); } catch(Throwable t){ System.out.println("  init threw "+t); }
            System.out.println("[INIT 0x4000001] "+cnt[0]+" instrs RET="+(ri==null?"null":readObj(vm,ri.longValue())));
            // ★ #24 Widevine collect: 0x122b00 = lazy-singleton getter (guard 0x1fc210, cache 0x1fc208) → triggers MediaDrm collect
            if ("1".equals(System.getenv("MSB_WIDEVINE"))) {
                long wtgt = Long.decode(System.getProperty("WV_FN","0x122b00"));
                System.out.println("[WIDEVINE] calling 0x"+Long.toHexString(wtgt)+" — trace BL targets...");
                final java.util.List<Long> wcalls = new java.util.ArrayList<>();
                final long wbase = base;
                CodeHook wh = new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                    try { byte[] ib=b.mem_read(a,4); int insn=(ib[0]&0xff)|((ib[1]&0xff)<<8)|((ib[2]&0xff)<<16)|((ib[3]&0xff)<<24);
                        if ((insn&0xfc000000)==0x94000000){ int imm=insn&0x03ffffff; if((imm&0x02000000)!=0) imm-=0x04000000; wcalls.add(a+((long)imm*4)-wbase); }
                    } catch(Throwable t){} }
                    public void onAttach(UnHook un){} public void detach(){} };
                emu.getBackend().hook_add_new(wh, base+0x30000, base+0x180000, null);
                cnt[0]=0;
                boolean reachedMediaDrm[]={false};
                final long ENVPEER = envP.peer;
                final java.util.Set<Long> ENVFN = new java.util.HashSet<>(java.util.Arrays.asList(
                    0x13b084L,0x13b098L,0x13b128L,0x13b150L,0x13b208L,0x13b2d8L,0x13bb70L,0x13be48L,0x13c054L,0x13c2c4L,
                    0x13c3acL,0x13c3d0L,0x13c3f0L,0x13c4d8L,0x13c76cL,0x13c8c0L,0x13cae8L,0x13cd10L,0x13cf30L,0x13d12cL,
                    0x13d328L,0x13d538L,0x13d864L,0x13db38L,0x13dbfcL,0x13dd7cL,0x13de2cL,0x13de9cL,0x13dfe8L,0x13b6f0L,0x13b80cL));
                final boolean[] inDrv = {false};
                final long BASE = base;
                CodeHook mdh = new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                    long off=a-BASE;
                    if(off==0x12305cL){ reachedMediaDrm[0]=true; b.reg_write(Arm64Const.UC_ARM64_REG_X0, ENVPEER); }   // collect entry: force x0=JNIEnv
                    else if(ENVFN.contains(off)){ b.reg_write(Arm64Const.UC_ARM64_REG_X0, ENVPEER); }                  // JNI env-helpers
                    else if(off==0x172580L && inDrv[0]){ b.reg_write(Arm64Const.UC_ARM64_REG_X0, 1L);                  // strcmp -> "differ" (force pass-path)
                        long lr=b.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue(); b.reg_write(Arm64Const.UC_ARM64_REG_PC, lr); } }
                    public void onAttach(UnHook un){} public void detach(){} };
                emu.getBackend().hook_add_new(mdh, base+0x120000, base+0x180000, null);
                vm.setVerbose(true);
                try {
                    Number mgr = mod.callFunction(emu, 0x122b00L);
                    long m = mgr==null?0:mgr.longValue();
                    System.out.println("[WIDEVINE] manager 0x122b00 -> 0x"+Long.toHexString(m));
                    long tls = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_TPIDR_EL0).longValue();
                    writeLong(emu, tls+0x28, ENVPEER);   // seed JNIEnv into TLS[0x28]
                    if ("1".equals(System.getProperty("WV_DRIVER"))) {
                        // recipe (q3): drive collect+STORE fn 0x122b90 → collect runs + stores #24 into [0x1fbe00].
                        emu.getBackend().mem_write(base+0x1fbe04, new byte[4]);  // counter gate: [0x1fbe04]=0 (<=3)
                        System.out.println("   [WV] pre-write counter [0x1fbe04]=0; driving 0x122b90(m=0x"+Long.toHexString(m)+")");
                        // build ctx chain: [ctx]->p8; [p8]->p22; [p22]=envP  (0x122b90: x8=[x0], x22=[x8], collect x0=[x22])
                        UnidbgPointer p22 = emu.getMemory().malloc(8,false).getPointer(); p22.setLong(0, ENVPEER);
                        UnidbgPointer p8  = emu.getMemory().malloc(8,false).getPointer(); p8.setLong(0, p22.peer);
                        UnidbgPointer pctx= emu.getMemory().malloc(8,false).getPointer(); pctx.setLong(0, p8.peer);
                        long DARG = "m".equals(System.getProperty("WV_DARG")) ? m : ("env".equals(System.getProperty("WV_DARG")) ? ENVPEER : pctx.peer);
                        wcalls.clear(); cnt[0]=0; inDrv[0]=true;
                        Number cr=null; try { cr = mod.callFunction(emu, 0x122b90L, DARG); } finally { inDrv[0]=false; }
                        System.out.println("[WIDEVINE driver 0x122b90] "+cnt[0]+" instrs ret=0x"+Long.toHexString(cr==null?0:cr.longValue())+" reachedMediaDrm="+reachedMediaDrm[0]);
                        // read the [0x1fbe00] container (libc++ std::string {cap|1,len,ptr} or {shortlen,inline})
                        System.out.println("   [WV] [0x1fbe00] after = "+readCpp(emu, base+0x1fbe00));
                        byte[] c=emu.getBackend().mem_read(base+0x1fbe00,32); StringBuilder h=new StringBuilder(); for(byte bb:c) h.append(String.format("%02x",bb&0xff));
                        System.out.println("   [WV] [0x1fbe00] raw32="+h);
                    } else if ("1".equals(System.getProperty("WV_COLLECT"))) {
                        wcalls.clear(); cnt[0]=0;
                        long WVARG = Long.decode(System.getProperty("WV_ARG","0"))==1 ? ENVPEER : m;
                        Number cr = mod.callFunction(emu, 0x12305cL, WVARG);
                        System.out.println("[WIDEVINE collect 0x12305c] "+cnt[0]+" instrs ret=0x"+Long.toHexString(cr==null?0:cr.longValue())+" reachedMediaDrm="+reachedMediaDrm[0]);
                    }
                }
                catch(Throwable t){ System.out.println("[WIDEVINE] threw "+t+" reachedMediaDrm="+reachedMediaDrm[0]); }
                System.out.print("[WIDEVINE BL-trace] ");
                for (Long c : wcalls) System.out.print("0x"+Long.toHexString(c)+" ");
                System.out.println();
            }
            // ★ REAL SIGN = 0x9ecc0(char* url, char* cookie) -> char* header ("X-Argus\r\n...")
            String url = new String(java.nio.file.Files.readAllBytes(new File("url.bin").toPath()), StandardCharsets.UTF_8);
            String cookie = new String(java.nio.file.Files.readAllBytes(new File("cookie.bin").toPath()), StandardCharsets.UTF_8);
            System.out.println("  url="+url.substring(0,Math.min(80,url.length()))+"...  headerblock="+cookie.length()+"B");
            UnidbgPointer urlP = allocCStr(emu, url);
            UnidbgPointer ckP  = allocCStr(emu, cookie);
            final long[] slast={0};
            emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){ slast[0]=a; }
                public void onAttach(UnHook un){} public void detach(){} }, mod.base+0x9ecc0, mod.base+0xa0000, null);
            long guardBefore = emu0.getBackend().mem_read(mod.base+0x1f4a08,1)[0]&0xff;
            System.out.println("  guard *(0x1f4a08) before sign = "+guardBefore);
            cnt[0]=0; lastpc[0]=0; calls.clear();
            Number sr=null; try { sr=mod.callFunction(emu, 0x9ecc0L, urlP.peer, ckP.peer); } catch(Throwable t){ System.out.println("  0x9ecc0 threw "+t); }
            long retp = sr==null?0:sr.longValue();
            String hdr = retp==0?"(null)":readCStr(emu, retp);
            System.out.printf("[REALSIGN 0x9ecc0] %d instrs, exit-PC=0x%x retptr=0x%x%n", cnt[0], slast[0]-mod.base, retp);
            System.out.println("  HEADER = " + (hdr==null?"null":hdr.replace("\r\n"," | ")));
            System.out.println("  [AES-CBC hits during sign="+aesHits[0]+"]");
            // scan unidbg memory for report protobuf magic (field#1=1077940818 -> 08 d2 a4 80 82 04)
            byte[] magic={0x08,(byte)0xd2,(byte)0xa4,(byte)0x80,(byte)0x82,0x04};
            long[] scanBases={0x40000000L, 0xbf000000L, 0xc0000000L, mod.base+0x30000000L};
            int found=0;
            for(long sb: scanBases){
                for(long off=0; off<0x400000 && found<5; off+=0x1000){
                    try{ byte[] page=emu.getBackend().mem_read(sb+off,0x1000);
                        for(int i=0;i<page.length-6;i++){ boolean m=true; for(int k=0;k<6;k++) if(page[i+k]!=magic[k]){m=false;break;}
                            if(m){ found++; System.out.printf("   [REPORT MAGIC @0x%x] ",sb+off+i);
                                byte[] rpt=emu.getBackend().mem_read(sb+off+i,Math.min(700,0x1000-i));
                                java.nio.file.Files.write(new File("/tmp/report_"+found+".bin").toPath(), rpt);
                                StringBuilder hx=new StringBuilder(); for(int j=0;j<48;j++) hx.append(String.format("%02x",rpt[j]&0xff));
                                System.out.println(hx+" (saved /tmp/report_"+found+".bin)"); if(found>=5)break; } }
                    }catch(Throwable t){}
                }
            }
            System.out.println("  [report-magic scan: found="+found+"]");
            // ---- #24 WIDEVINE COLLECT recon (-Dwv=1): drive collect func, capture JNI names / crash PC ----
            if (Boolean.getBoolean("wv")) {
                final long[] wvpc={0}; final int[] wvn={0}; final boolean[] hitJni={false};
                emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){ wvpc[0]=a; wvn[0]++; }
                    public void onAttach(UnHook un){} public void detach(){} }, mod.base+0x122000, mod.base+0x124000, null);
                // definitive marker: did we reach the MediaDrm/UUID JNI sites 0x1231e4 / 0x1232cc?
                emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                    hitJni[0]=true; System.out.println("[WV] *** REACHED JNI site 0x"+Long.toHexString(a-mod.base)+" ***"); }
                    public void onAttach(UnHook un){} public void detach(){} }, mod.base+0x1231e4, mod.base+0x1231e5, null);
                emu.getBackend().hook_add_new(new CodeHook(){ public void hook(Backend b,long a,int sz,Object u){
                    hitJni[0]=true; System.out.println("[WV] *** REACHED JNI site 0x"+Long.toHexString(a-mod.base)+" ***"); }
                    public void onAttach(UnHook un){} public void detach(){} }, mod.base+0x1232cc, mod.base+0x1232cd, null);
                // dump context/config globals populated by init (notes/57 §9-11)
                long[] G={0x1f4a60,0x1f4a08,0x1f4a48,0x1f4a68,0x1f4a40,0x1f3ce0,0x1f3f58,0x1fc220,0x1f3c80};
                System.out.println("[WV] context globals after init/sign:");
                long ctx=0;
                for(long g:G){ long v=readLong(emu, mod.base+g); if(g==0x1f4a60) ctx=v;
                    System.out.printf("     [0x%x] = 0x%x%n", g, v); }
                // candidate `this` for collector: real ctx object [0x1f4a60]; fallback fake vtable.
                UnidbgPointer vtbl = emu.getMemory().malloc(0x400,true).getPointer();
                UnidbgPointer fake = emu.getMemory().malloc(0x400,true).getPointer(); fake.setLong(0, vtbl.peer);
                java.util.List<long[]> tries = new java.util.ArrayList<>();
                if(ctx!=0){ tries.add(new long[]{0x122b90L, ctx}); tries.add(new long[]{0x12305cL, ctx}); }
                tries.add(new long[]{0x122b90L, fake.peer});
                for(long[] tc : tries){
                    long tgt=tc[0], self=tc[1]; wvpc[0]=0; wvn[0]=0; hitJni[0]=false;
                    System.out.printf("[WV] drive 0x%x with x0=0x%x %s%n", tgt, self, (self==ctx?"(REAL ctx)":"(fake)"));
                    try { Number wr=mod.callFunction(emu, tgt, self);
                        System.out.printf("[WV] 0x%x RET=%s instrs=%d hitJNI=%b%n", tgt, wr, wvn[0], hitJni[0]); }
                    catch(Throwable t){ System.out.printf("[WV] 0x%x stopped @0x%x instrs=%d hitJNI=%b : %s %s%n",
                        tgt, wvpc[0]-mod.base, wvn[0], hitJni[0], t.getClass().getSimpleName(), t.getMessage()); }
                }
            }
        } catch (Throwable t){ System.out.println("[SIGN-STOP] "+t); }
        emu.close();
    }
    static UnidbgPointer mkCpp(Memory mem, String v){ byte[] d=v.getBytes();
        UnidbgPointer data=mem.malloc(d.length+1,false).getPointer(); data.write(0,d,0,d.length); data.setByte(d.length,(byte)0);
        UnidbgPointer st=mem.malloc(24,false).getPointer(); st.setLong(0,(d.length<<1)); st.setLong(8,data.peer); return st; }
    static void e2(Emulator<?> e,long a){ e.getBackend().mem_write(a,new byte[24]); }
    static UnidbgPointer allocCStr(Emulator<?> e, String v){ byte[] d=v.getBytes(StandardCharsets.UTF_8);
        UnidbgPointer p=e.getMemory().malloc(d.length+1,false).getPointer(); p.write(0,d,0,d.length); p.setByte(d.length,(byte)0); return p; }
    static String readCStr(Emulator<?> e, long addr){ try { StringBuilder sb=new StringBuilder();
        for(int i=0;i<8192;i++){ byte b=e.getBackend().mem_read(addr+i,1)[0]; if(b==0) break; sb.append((char)(b&0xff)); } return sb.toString(); } catch(Throwable t){ return "?"+t; } }
    static Object msbCallback(int cmd){
        switch(cmd){
            case 0x10003:    return "/data/user/0/com.zhiliaoapp.musically/files";  // data-dir
            case 0x1000011:  return "45.7.3";
            case 0x1000010:  return "2024507030";
            case 0x100000f:  return "com.zhiliaoapp.musically";
            case 0x1000012:  return "1233";      // aid
            default:         return null;        // 0x1000001 decode / 0x1000022 keva: null for now
        }
    }
    static String readObj(VM vm, long h){ try { DvmObject<?> o=vm.getObject((int)h); if(o==null) return "null-dvm"; return "["+o.getClass().getName()+"] "+decodeObj(o,0); } catch(Throwable t){ return "?"+t; } }
    static String decodeObj(DvmObject<?> o, int depth){ if(o==null||depth>3) return "null"; Object v=o.getValue();
        if(v instanceof byte[]){ byte[] b=(byte[])v; StringBuilder sb=new StringBuilder("byte["+b.length+"]="); for(int i=0;i<Math.min(b.length,40);i++) sb.append(String.format("%02x",b[i])); if(new String(b).chars().allMatch(c->c>=32&&c<127)) sb.append(" ('"+new String(b,0,Math.min(b.length,80))+"')"); return sb.toString(); }
        if(o instanceof ArrayObject){ Object[] arr=((ArrayObject)o).getValue(); StringBuilder sb=new StringBuilder("Array["+arr.length+"]{"); for(int i=0;i<arr.length;i++){ sb.append("\n    ["+i+"] "); sb.append(arr[i] instanceof DvmObject?decodeObj((DvmObject<?>)arr[i],depth+1):String.valueOf(arr[i])); } return sb.append("}").toString(); }
        return o.getClass().getSimpleName()+":"+String.valueOf(v); }
    static String readCpp(Emulator<?> e, long p){ try {
        byte[] h=e.getBackend().mem_read(p,24);
        long l4=(h[4]&0xffL)|((h[5]&0xffL)<<8)|((h[6]&0xffL)<<16)|((h[7]&0xffL)<<24);
        long p8=0; for(int i=15;i>=8;i--) p8=(p8<<8)|(h[i]&0xffL);
        if(l4>0&&l4<256&&p8!=0){return new String(e.getBackend().mem_read(p8,(int)l4));}
        if((h[0]&1)==0){int n=(h[0]&0xff)>>1; if(n>0&&n<23) return new String(e.getBackend().mem_read(p+1,n));}
    } catch(Throwable t){} return "?"; }
    static void wl(Emulator<?> e,long a,long v){ writeLong(e,a,v); }
    static long readLong(Emulator<?> e,long a){byte[] b=e.getBackend().mem_read(a,8);long v=0;for(int i=7;i>=0;i--)v=(v<<8)|(b[i]&0xffL);return v;}
    static long readLE(byte[] b,int off){long v=0;for(int i=7;i>=0;i--)v=(v<<8)|(b[off+i]&0xffL);return v;}
    static void writeLong(Emulator<?> e,long a,long v){byte[] b=new byte[8];for(int i=0;i<8;i++){b[i]=(byte)(v&0xff);v>>=8;}e.getBackend().mem_write(a,b);}
}
