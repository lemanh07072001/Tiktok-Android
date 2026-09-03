package tt;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.arm.backend.EventMemHook;
import com.github.unidbg.arm.backend.Backend;
import unicorn.UnicornConst;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;
import java.io.File;
import java.util.*;

/** Mac unidbg signer bootstrap — libmetasec_ov.so INITIALIZES on macOS (JNI_OnLoad completes).
 *  Layers solved: GetSuperClass(Object)->null; 37 libc++ imports stubbed (Arm64Svc + GOT patch).
 *  REMAINING for a full signer = the sign-call ABI (metasec protocol: entry 0x9ecc0/0x11a1e0,
 *  cmd codes + arg struct + get_seed + MSB_DEVSTATE) — see notes/57 §3-4. */
public class LoadTest {
    static long tick = 0;
    static final File STORE_DIR = new File("state/msstate_7678616678053643790/.msdata/mssdk/ov");
    public static void main(String[] args) throws Exception {
        Properties got = new Properties();
        got.load(LoadTest.class.getResourceAsStream("/got_symbols.properties"));
        AndroidEmulator emu = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.zhiliaoapp.musically").build();
        Memory memory = emu.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        emu.getSyscallHandler().addIOResolver(new IOResolver() {
            public FileResult resolve(Emulator e, String path, int oflags) {
                System.out.println("[FILE] open: " + path);
                // Serve the real store files (.msp_/.mss_/.msf3_/.msfs_) from the device state dir,
                // whatever directory the .so builds — match by basename.
                String bn = path;
                int sl = path.lastIndexOf('/'); if (sl >= 0) bn = path.substring(sl+1);
                if (bn.startsWith(".msp_") || bn.startsWith(".mss_") || bn.startsWith(".msf3_") || bn.startsWith(".msfs_")) {
                    File real = new File(STORE_DIR, bn);
                    if (real.exists()) {
                        System.out.println("       -> serving " + real);
                        return FileResult.success(new com.github.unidbg.linux.file.SimpleFileIO(oflags, real, path));
                    }
                }
                return null;
            }
        });
        VM vm = emu.createDalvikVM();
        vm.setVerbose(false);
        vm.setJni(new AbstractJni() {
            @Override public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass c, DvmMethod m, VarArg va) {
                System.out.println("[MS-CB] callStaticObjectMethod " + m.getMethodName());
                return null;
            }
            @Override public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass c, DvmMethod m, VaList va) {
                System.out.println("[MS-CB] callStaticObjectMethodV " + m.getMethodName());
                return null;
            }
        });
        DvmClass object = vm.resolveClass("java/lang/Object");
        vm.resolveClass("com/bytedance/mobsec/metasec/ov/MS", object);
        DalvikModule dmod = vm.loadLibrary(new File("native/libmetasec_ov.so"), true);
        Module mod = dmod.getModule();
        long base = mod.base;
        System.out.printf("[OK] base=0x%x, 147 init ctors ran%n", base);

        SvcMemory svc = emu.getSvcMemory();
        List<Module> mods = new ArrayList<>(memory.getLoadedModules());
        int stubbed = 0;
        for (String k : got.stringPropertyNames()) {
            long gotOff = Long.parseLong(k, 16);
            long val = readLong(emu, base + gotOff);
            boolean resolved = false;
            for (Module m : mods) if (val >= m.base && val < m.base + m.size) { resolved = true; break; }
            if (resolved) continue;
            final String sym = got.getProperty(k);
            UnidbgPointer stub = svc.registerSvc(new Arm64Svc() {
                @Override public long handle(Emulator<?> e) {
                    if (sym.contains("try_lock")) return 1;
                    if (sym.contains("clock") && sym.contains("now")) return (tick += 1_000_000);
                    return 0;
                }
            });
            writeLong(emu, base + gotOff, stub.peer);
            stubbed++;
        }
        System.out.println("[STUB] patched " + stubbed + " unresolved libc++ imports");

        final java.util.List<Long> jpc = new java.util.ArrayList<>();
        emu.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook(){
            public void hook(Backend b,long a,int sz,Object u){ long o=a-base; if(o>=0x119b40&&o<0x11a0d0 && jpc.size()<4000) jpc.add(o); }
            public void onAttach(com.github.unidbg.arm.backend.UnHook un){} public void detach(){}
        }, base+0x119b40, base+0x11a0d0, null);
        Debugger dbg = emu.attach();
        final long[] msClass = {0};
        dbg.addBreakPoint(mod, 0x119b78, (e, a) -> {   // after FindClass(MS): capture jclass
            msClass[0] = e.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            System.out.printf("[CC] captured MS jclass=0x%x%n", msClass[0]);
            return true;
        });
        dbg.addBreakPoint(mod, 0x119ba0, (e, a) -> {   // GetSuperClass(Object)=null
            e.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, 0L);
            e.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, base + 0x119ba4);
            return true;
        });
        dbg.addBreakPoint(mod, 0x119c38, (e, a) -> {   // cbz x0 -> skip register; force x0=MS jclass to REGISTER
            long x0 = e.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            if (x0 == 0 && msClass[0] != 0) { e.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, msClass[0]); System.out.println("[CC] forced x0=MS jclass -> register path"); }
            return true;
        });
        try {
            dmod.callJNI_OnLoad(emu);
            System.out.println("[SUCCESS] JNI_OnLoad completed — signer .so initialized on Mac.");
            System.out.println("[CC] class-check forced-register: "+jpc.size()+" instrs (RegisterNatives + MS.a/MS.b cached)");
            long[] cfgg = {0x1f4a08,0x1f3ce0,0x1f3f58,0x1f4a48,0x1f4a68,0x1f4a60,0x1f4a40};
            for (long g: cfgg) System.out.printf("  cfg[0x%x]=0x%x%n", g, readLong(emu, base+g));
            System.out.println("[CFG] config globals empty (0) — need MSManager.init (notes/57 §10). MS.a/MS.b callbacks registered.");
            System.out.println("[CFG] config-setter=0x4f3b0 (writes cfg-struct); loops if called isolated — needs full MSManager.init context. notes/57 §11.");
        } catch (Throwable ex) {
            System.out.println("[STOP] JNI_OnLoad: " + ex);
        }
        emu.close();
    }
    static UnidbgPointer mkCppStr(Memory mem, String v){
        byte[] d = v.getBytes();
        UnidbgPointer data = mem.malloc(d.length+1, false).getPointer(); data.write(0, d, 0, d.length); data.setByte(d.length,(byte)0);
        UnidbgPointer st = mem.malloc(24, false).getPointer();
        st.setLong(0, (d.length | 1));   // __cap_ | long-flag(LSB)
        st.setLong(8, d.length);          // __size_
        st.setLong(16, data.peer);        // __data_
        return st;
    }
    static long readLong(Emulator<?> e, long a){ byte[] b=e.getBackend().mem_read(a,8); long v=0; for(int i=7;i>=0;i--) v=(v<<8)|(b[i]&0xffL); return v; }
    static void writeLong(Emulator<?> e, long a, long v){ byte[] b=new byte[8]; for(int i=0;i<8;i++){b[i]=(byte)(v&0xff); v>>=8;} e.getBackend().mem_write(a,b); }
}
