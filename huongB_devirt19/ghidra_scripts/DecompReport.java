import ghidra.app.script.GhidraScript; import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address; import ghidra.program.model.listing.*;
public class DecompReport extends GhidraScript {
  public void run() throws Exception {
    String p=System.getenv("DECOMP_OFFS"); if(p==null)p="0x118e54";
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    for(String os: p.split(",")){ long off=Long.decode(os.trim());
      Address a=currentProgram.getImageBase().add(off); Function f=getFunctionContaining(a);
      if(f==null){println("=== NO FUNC "+os+" ==="); continue;}
      println("\n@@@@@ 0x"+Long.toHexString(off)+" -> "+f.getName()+" @@@@@");
      DecompileResults r=dec.decompileFunction(f,60,monitor);
      if(r!=null&&r.decompileCompleted()){String c=r.getDecompiledFunction().getC(); if(c.length()>5000)c=c.substring(0,5000)+"...trunc"; println(c);} else println("(fail)");
    }
    dec.dispose();
  }
}
