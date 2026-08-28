// Diagnostic: dump the data table around 0x395090 (found to contain a
// pointer to FUN_0017cdd0, a likely scene/state dispatcher entry point) as
// an array of uint32 words/pointers, and find what code reads from this
// table (the generic dispatcher that would call table[state]()).
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class DumpSceneTable extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        println("=== table around 0x395050-0x395110 ===");
        for (long off = 0x395050L; off <= 0x395110L; off += 4) {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
            try {
                int v = mem.getInt(a);
                Function fn = null;
                if (v > 0 && v < 0x4000000) {
                    Address fa = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v & 0xFFFFFFFFL);
                    fn = currentProgram.getFunctionManager().getFunctionAt(fa);
                }
                println(String.format("0x%x: 0x%08x%s", off, v, fn != null ? " -> " + fn.getName() : ""));
            } catch (Exception e) {
                println(String.format("0x%x: <unreadable>", off));
            }
        }

        println("=== XREFs to the table base region (0x395090) ===");
        Address base = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x395090");
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(base);
        int c = 0;
        while (it.hasNext() && c < 20) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  ref: " + r.getReferenceType() + "@" + from + (fn != null ? " (in " + fn.getName() + ")" : " (no fn)"));
            c++;
        }
        println("  total: " + c);
    }
}
