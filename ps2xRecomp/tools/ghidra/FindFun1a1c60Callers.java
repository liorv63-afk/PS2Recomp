// Diagnostic: find callers of FUN_001a1c60 (the sole caller of the real
// "open file for async streaming" API, FUN_0019f2f0, confirmed never
// executed live) -- continuing the backward chase for what's supposed to
// trigger asset loading in DQ8.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindFun1a1c60Callers extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x1a1c60");
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(start);
        int c = 0;
        while (it.hasNext() && c < 30) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Function callerFn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("caller: " + r.getReferenceType() + "@" + from + (callerFn != null ? " (in " + callerFn.getName() + " entry=" + callerFn.getEntryPoint() + ")" : " (no fn)"));
            c++;
        }
        println("total (capped 30): " + c);
    }
}
