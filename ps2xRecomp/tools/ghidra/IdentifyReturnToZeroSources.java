// Diagnostic: identify which functions contain the two addresses whose
// return-to-zero events dominate the tail of thread 1's execution just
// before its final exit (0x1605b8, 0x25aa10), plus their callers.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class IdentifyReturnToZeroSources extends GhidraScript {
    void identify(String addrStr) throws Exception {
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrStr);
        Function fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
        println("=== " + addrStr + " -> " + (fn != null ? fn.getName() + " (" + fn.getEntryPoint() + "-" + fn.getBody().getMaxAddress() + ")" : "NO FUNCTION") + " ===");
        if (fn == null) return;
        Address start = fn.getEntryPoint();
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(start);
        int c = 0;
        while (it.hasNext() && c < 10) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Function callerFn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  caller: " + r.getReferenceType() + "@" + from + (callerFn != null ? " (in " + callerFn.getName() + ")" : " (no fn)"));
            c++;
        }
    }

    @Override
    public void run() throws Exception {
        identify("0x1605b8");
        identify("0x25aa10");
    }
}
