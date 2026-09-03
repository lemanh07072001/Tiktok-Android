// Tìm & decompile hàm THẬT build slot16: chứa `bl 0x891f4` tại ~0x88858.
// Liệt kê mọi callsite (bl/blr) + biên hàm quanh 0x88000-0x89400.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.pcode.PcodeOp;
import java.io.*;
import java.util.*;

public class GhidraSlot16Build extends GhidraScript {
    static final String OUTDIR =
        "/Users/lemanh/Documents/Tiktok-Android/huongB_devirt19/_ghidra_out";
    Address A(long off){ return currentProgram.getImageBase().add(off); }

    @Override public void run() throws Exception {
        new File(OUTDIR).mkdirs();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();
        DecompInterface dec = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        dec.setOptions(opts); dec.toggleCCode(true);
        dec.setSimplificationStyle("decompile");
        dec.openProgram(currentProgram);

        // 1) hàm chứa các site quan trọng
        long[] probes = {0x88858L, 0x88834L, 0x887e0L, 0x88ab8L, 0x89320L};
        LinkedHashSet<Long> fns = new LinkedHashSet<Long>();
        for (long p : probes) {
            Function f = fm.getFunctionContaining(A(p));
            long ep = (f!=null)? f.getEntryPoint().subtract(currentProgram.getImageBase()) : -1;
            Address end = (f!=null)? f.getBody().getMaxAddress() : null;
            println("site 0x"+Long.toHexString(p)+" → fn 0x"
                + (f!=null?Long.toHexString(ep):"?")
                + (end!=null? "  end~0x"+Long.toHexString(end.subtract(currentProgram.getImageBase())):"")
                + (f!=null? "  "+f.getName():""));
            if (f!=null) fns.add(ep);
        }

        // 2) mọi callsite trong dải 0x87cf4..0x89400 (sau ret của 0x879d8)
        println("\n=== callsites trong 0x87cf4..0x89400 ===");
        Address a = A(0x87cf4), stop = A(0x89400);
        InstructionIterator it = lst.getInstructions(a, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(stop) > 0) break;
            String mn = ins.getMnemonicString();
            if (mn.equals("bl") || mn.equals("blr") || mn.equals("br")) {
                long off = ins.getAddress().subtract(currentProgram.getImageBase());
                Address[] flows = ins.getFlows();
                StringBuilder tg = new StringBuilder();
                if (flows!=null) for (Address fl: flows)
                    tg.append(" →0x").append(Long.toHexString(fl.subtract(currentProgram.getImageBase())));
                println("  0x"+Long.toHexString(off)+"  "+mn+"  "+ins.toString()+tg);
            }
        }

        // 3) decompile các hàm tìm được
        println("\n=== decompile ===");
        for (long ep : fns) {
            Function f = fm.getFunctionContaining(A(ep));
            if (f==null) continue;
            DecompileResults r = dec.decompileFunction(f, 180, monitor);
            String c = (r!=null && r.decompileCompleted())
                ? r.getDecompiledFunction().getC() : "// FAIL: "+(r!=null?r.getErrorMessage():"null")+"\n";
            File fp = new File(OUTDIR, "build_"+Long.toHexString(ep)+".c");
            FileWriter w = new FileWriter(fp); w.write(c); w.close();
            println("  0x"+Long.toHexString(ep)+" "+f.getName()+" (C "+c.length()+"B) → build_"+Long.toHexString(ep)+".c");
        }
        dec.dispose();
    }
}
