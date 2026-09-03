// Tìm mọi hàm tham chiếu tới registry .bss 0x1f4990 (map chứa slot16).
// Reader = lookup (0x879d8 → 0x8913c). Writer = insert (dựng hex slot16 rồi chèn).
// Decompile từng hàm → tìm writer = nơi derive slot16 lúc session-init.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.util.*;

public class GhidraXrefs extends GhidraScript {
    // các .bss/.data global cần soi xref (offset file = vaddr)
    static final long[] TARGETS = {0x119108L, 0x20e224L, 0x20b010L};  // const-key decryptor + cipher + keysched
    static final String OUTDIR =
        "/Users/lemanh/Documents/Tiktok-Android/huongB_devirt19/_ghidra_out";

    Address A(long off){ return currentProgram.getImageBase().add(off); }

    @Override public void run() throws Exception {
        new File(OUTDIR).mkdirs();
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface dec = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        dec.setOptions(opts); dec.toggleCCode(true);
        dec.setSimplificationStyle("decompile");
        dec.openProgram(currentProgram);
        long IB = currentProgram.getImageBase().getOffset();

        Set<Long> seen = new LinkedHashSet<Long>();
        for (long t : TARGETS) {
            println("\n===== xref → 0x" + Long.toHexString(t)
                + " (Ghidra " + A(t) + ") =====");
            for (Reference ref : getReferencesTo(A(t))) {
                Function fc = fm.getFunctionContaining(ref.getFromAddress());
                String ty = ref.getReferenceType().toString();
                long ep = (fc!=null)? fc.getEntryPoint().subtract(currentProgram.getImageBase()) : -1;
                println("  " + ref.getFromAddress() + "  " + ty
                    + "  in fn 0x" + (fc!=null? Long.toHexString(ep):"?")
                    + (fc!=null? " "+fc.getName():""));
                if (fc!=null) seen.add(ep);
            }
        }

        println("\n===== decompile các hàm chạm registry (writer=insert?) =====");
        for (long off : seen) {
            Function f = fm.getFunctionContaining(A(off));
            if (f==null) continue;
            DecompileResults r = dec.decompileFunction(f, 120, monitor);
            String c = (r!=null && r.decompileCompleted())
                ? r.getDecompiledFunction().getC() : "// FAIL\n";
            File fp = new File(OUTDIR, "xref_"+Long.toHexString(off)+".c");
            FileWriter w = new FileWriter(fp); w.write(c); w.close();
            // heuristic writer: có _Znwm/_Znam (new node) + insert/_M_ + build hex
            String lc = c.toLowerCase();
            boolean alloc = lc.contains("_znwm(") || lc.contains("_znam(") || c.contains("operator.new");
            boolean insert = lc.contains("insert") || lc.contains("_m_") || c.contains("_Rb_tree");
            long unhex = countHas(c,"1891f4")+countHas(c,"891f4");
            println("  0x"+Long.toHexString(off)+"  "+f.getName()
                +"  (C "+c.length()+"B, alloc="+alloc+", insert-ish="+insert
                +", unhex="+unhex+")  → xref_"+Long.toHexString(off)+".c");
        }
        dec.dispose();
    }
    static long countHas(String h,String n){ long c=0; int i=0;
        while((i=h.indexOf(n,i))>=0){c++;i+=n.length();} return c; }
}
