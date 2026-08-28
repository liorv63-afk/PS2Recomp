// Diagnostic: find callers of FUN_0019f2f0 (the real "open file for async
// streaming" API, per decompiled path-normalization + FUN_0024dc60 slot
// allocation + FUN_0024e6e0(handle, path) call) -- the most direct lead yet
// for what SHOULD trigger real asset loading in DQ8.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindFun19f2f0Callers extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x19f2f0");
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
