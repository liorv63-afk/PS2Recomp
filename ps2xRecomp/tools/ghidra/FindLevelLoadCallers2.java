// Diagnostic: find callers of FUN_0034a160 and FUN_001ce350, both confirmed
// (via prior scripts) to be callers of FUN_001ce490 (the likely "load
// level/zone" function) that themselves never execute live -- continuing the
// backward chase one more hop.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindLevelLoadCallers2 extends GhidraScript {
    void dumpCallers(String startStr) throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(startStr);
        println("=== callers of " + startStr + " ===");
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(start);
        int c = 0;
        while (it.hasNext() && c < 30) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Function callerFn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  caller: " + r.getReferenceType() + "@" + from + (callerFn != null ? " (in " + callerFn.getName() + " entry=" + callerFn.getEntryPoint() + ")" : " (no fn)"));
            c++;
        }
        println("  total (capped 30): " + c);
    }

    @Override
    public void run() throws Exception {
        dumpCallers("0x34a160");
        dumpCallers("0x1ce350");
    }
}
