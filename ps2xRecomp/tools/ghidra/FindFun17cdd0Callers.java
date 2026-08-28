// Diagnostic: find callers of FUN_0017cdd0 -- calls the semaphore-66 lock
// helper 4 times AND the level-load chain, likely a central scene/game-state
// dispatcher. Continuing the backward chase for DQ8's real trigger point.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindFun17cdd0Callers extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x17cdd0");
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
