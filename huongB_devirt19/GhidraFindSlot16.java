// Ghidra headless GhidraScript (Java — không cần PyGhidra).
// Khoanh vùng slot16 producer: unhex decoder @0x891f4 có nhiều caller;
// hàm nào build chuỗi 32-hex feed vào unhex = producer.
// Chạy qua run_ghidra_slot16.sh.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import java.io.File;
import java.io.FileWriter;
import java.util.*;

public class GhidraFindSlot16 extends GhidraScript {
    static final long UNHEX = 0x891f4L;
    static final long SM3_DRV = 0x9fdacL;                 // consumer slot16 (SM3 driver)
    static final long[] CAND = {0x10e224L,0x10b010L,0x118ffcL};  // file offsets: const-key cipher + key-derive(SHA1?) + key-init
    static final String OUTDIR =
        "/Users/lemanh/Documents/Tiktok-Android/huongB_devirt19/_ghidra_out";

    Address A(long off){ return currentProgram.getImageBase().add(off); }

    Function fnAt(long off){
        return currentProgram.getFunctionManager().getFunctionContaining(A(off));
    }

    @Override
    public void run() throws Exception {
        new File(OUTDIR).mkdirs();
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface dec = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        dec.setOptions(opts);
        dec.toggleCCode(true);
        dec.toggleSyntaxTree(true);
        dec.setSimplificationStyle("decompile");
        boolean opened = dec.openProgram(currentProgram);
        println("=== decompiler openProgram = " + opened
            + (opened? "" : "  ERR: " + dec.getLastMessage()));

        println("=== image base = " + currentProgram.getImageBase());

        // callers của UNHEX (mọi caller, không chỉ 5 tĩnh — để chắc)
        println("=== callers of UNHEX 0x" + Long.toHexString(UNHEX) + " ===");
        Set<Long> dynCallers = new LinkedHashSet<Long>();
        for (Reference ref : getReferencesTo(A(UNHEX))) {
            if (ref.getReferenceType().isCall()) {
                Function fc = fm.getFunctionContaining(ref.getFromAddress());
                long ep = (fc!=null)? fc.getEntryPoint().subtract(currentProgram.getImageBase()) : -1;
                if (fc!=null) dynCallers.add(ep);
                println("  call@" + ref.getFromAddress()
                    + "  in fn 0x" + (fc!=null? Long.toHexString(ep):"?"));
            }
        }

        // gộp 5 ứng viên tĩnh + caller Ghidra tìm được
        LinkedHashSet<Long> cands = new LinkedHashSet<Long>();
        for (long c : CAND) cands.add(c);
        cands.addAll(dynCallers);

        Function sm3 = fnAt(SM3_DRV);
        println("\n=== SM3 driver (consumer) = "
            + (sm3!=null? sm3.getEntryPoint():"?") + " ===");

        // decompile từng ứng viên -> file + đếm hash-hint
        List<long[]> rank = new ArrayList<long[]>();   // {off, hashHint, cSize, feedsUnhex}
        Map<Long,String> names = new HashMap<Long,String>();
        for (long off : cands) {
            Function f = fnAt(off);
            if (f==null){ println("  0x"+Long.toHexString(off)+": NO FUNCTION"); continue; }
            DecompileResults r = dec.decompileFunction(f, 120, monitor);
            String c = (r!=null && r.decompileCompleted())
                ? r.getDecompiledFunction().getC()
                : "// decompile FAILED: " + (r!=null? r.getErrorMessage() : "null result") + "\n";
            String lc = c.toLowerCase();
            long hh = count(lc,"sha")+count(lc,"sm3")+count(lc,"md5")
                    + count(lc,"digest")+count(lc,"hex");
            long feeds = (c.contains(Long.toHexString(currentProgram.getImageBase()
                    .getOffset()+UNHEX)) || c.contains("891f4"))? 1:0;
            File fp = new File(OUTDIR, "fn_"+Long.toHexString(off)+".c");
            FileWriter w = new FileWriter(fp); w.write(c); w.close();
            names.put(off, f.getName());
            rank.add(new long[]{off, hh, c.length(), feeds});
            println("  0x"+Long.toHexString(off)+" -> "+f.getName()
                +"  (C "+c.length()+"B, hash-hint="+hh+", feeds-unhex="+feeds+")");
        }

        // RANK: feeds-unhex trước, rồi hash-hint
        Collections.sort(rank, new Comparator<long[]>(){
            public int compare(long[] a, long[] b){
                if (a[3]!=b[3]) return Long.compare(b[3],a[3]);
                return Long.compare(b[1],a[1]);
            }});
        println("\n=== RANK (feeds-unhex + hash-hint cao = ứng viên producer) ===");
        for (long[] x : rank)
            println("  0x"+Long.toHexString(x[0])+"  feeds-unhex="+x[3]
                +"  hash-hint="+x[1]+"  size="+x[2]+"  "+names.get(x[0]));
        println("\nĐọc _ghidra_out/fn_*.c của hàm top-rank = producer slot16.");
        dec.dispose();
    }

    static long count(String hay, String needle){
        long n=0; int i=0;
        while ((i=hay.indexOf(needle,i))>=0){ n++; i+=needle.length(); }
        return n;
    }
}
