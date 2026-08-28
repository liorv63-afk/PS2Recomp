// Diagnostic: find callers of FUN_001ce490 -- appears to be DQ8's real
// "load a level/zone with loading screen" function (contains a loop calling
// FUN_00165570, the entity/token dispatcher, plus loading-progress callback
// invocations). Continuing the backward chase.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindFun1ce490Callers extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x1ce490");
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
