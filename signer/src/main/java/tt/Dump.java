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
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import java.io.File;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Dump {
    static long tick = 0;
    static Emulator<?> emu0;
    static boolean[] signPhaseRef = {false};
    static VM theVM;
    static final File STORE_DIR = new File("state/msstate_7678616678053643790/.msdata/mssdk/ov");
    public static void main(String[] args) throws Exception {
        Properties got = new Properties();
        got.load(Dump.class.getResourceAsStream("/got_symbols.properties"));
        AndroidEmulator emu = AndroidEmulatorBuilder.for64Bit().setProcessName("com.zhiliaoapp.musically").build();
        emu0 = emu;
        Memory memory = emu.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        emu.getSyscallHandler().addIOResolver(new IOResolver() {
            public FileResult resolve(Emulator e, String path, int oflags) {
                String bn = path; int sl = path.lastIndexOf('/'); if (sl>=0) bn=path.substring(sl+1);
                if (bn.startsWith(".msp_")||bn.startsWith(".mss_")||bn.startsWith(".msf3_")||bn.startsWith(".msfs_")) {
                    File real = new File(STORE_DIR, bn);
                    if (real.exists()) { System.out.println("[FILE] SERVE " + real);
                        return FileResult.success(new com.github.unidbg.linux.file.SimpleFileIO(oflags, real, path)); }
                }
                return null;
            }
        });
        VM vm = emu.createDalvikVM(); theVM = vm;
        vm.setVerbose(false);
        vm.setJni(new AbstractJni() {
            public DvmObject<?> callObjectMethodV(BaseVM v, DvmObject<?> o, String sig, VaList va){
                if (sig.startsWith("b(")) { return null; }
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
        Debugger dbg = emu.attach();
        dbg.addBreakPoint(mod, 0x119ba0, (e,a) -> { e.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0,0L);
            e.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, base+0x119ba4); return true; });
        dbg.addBreakPoint(mod, 0xb0d10, (e,a) -> {
            long x1=e.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
            System.out.println("[READER 0xb0d10] key="+readCpp(e,x1)); return false; });
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
            // ★ REAL SIGN = 0x9ecc0(char* url, char* cookie) -> char* header ("X-Argus\r\n...")
            String url = "https://api16-normal-c-alisg.tiktokv.com/aweme/v2/feed/?device_platform=android&aid=1233";
            UnidbgPointer urlP = allocCStr(emu, url);
            UnidbgPointer ckP  = allocCStr(emu, "aweme_app_version=45.7.3&version_code=450703&device_platform=android&device_type=SM-G930F&os_version=8.0.0");
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
    static long readLong(Emulator<?> e,long a){byte[] b=e.getBackend().mem_read(a,8);long v=0;for(int i=7;i>=0;i--)v=(v<<8)|(b[i]&0xffL);return v;}
    static void writeLong(Emulator<?> e,long a,long v){byte[] b=new byte[8];for(int i=0;i<8;i++){b[i]=(byte)(v&0xff);v>>=8;}e.getBackend().mem_write(a,b);}
}
