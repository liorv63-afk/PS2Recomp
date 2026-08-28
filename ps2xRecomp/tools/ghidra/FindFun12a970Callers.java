// Diagnostic: find every caller of FUN_0012a970 (trivial wrapper for
// FUN_0012a670, the real cdrom-open initiator containing an infinite
// busy-wait retry loop on SID 0x80000597's bind, confirmed failing) to
// determine the blast radius -- is thread 9 the only caller, or do other
// subsystems also depend on this exact stuck loop?
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindFun12a970Callers extends GhidraScript {
    void dumpCallers(String startStr) throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(startStr);
        println("=== callers of " + startStr + " ===");
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(start);
        int c = 0;
        while (it.hasNext() && c < 30) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  caller: " + r.getReferenceType() + "@" + from + (fn != null ? " (in " + fn.getName() + ")" : " (no fn)"));
            c++;
        }
        println("  total (capped 30): " + c);
    }

    @Override
    public void run() throws Exception {
        dumpCallers("0x12a970");
        dumpCallers("0x12a670");
    }
}
