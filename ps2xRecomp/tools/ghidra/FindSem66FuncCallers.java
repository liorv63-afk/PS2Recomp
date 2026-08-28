// Diagnostic: find callers of the 4 functions that reference semaphore 66's
// storage slot, to determine whether the SignalSema(66) call sites found are
// ever actually reachable, and from where.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindSem66FuncCallers extends GhidraScript {
    void dumpCallers(String startStr) throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(startStr);
        println("=== callers of function at " + startStr + " ===");
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(start);
        int c = 0;
        while (it.hasNext() && c < 20) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Function callerFn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  caller: " + r.getReferenceType() + "@" + from + (callerFn != null ? " (in " + callerFn.getName() + ")" : " (no fn)"));
            c++;
        }
        if (c == 0) println("  (none found)");
    }

    @Override
    public void run() throws Exception {
        dumpCallers("0x163b50");
        dumpCallers("0x163c30");
        dumpCallers("0x163cc0");
        dumpCallers("0x1641c0");
    }
}
