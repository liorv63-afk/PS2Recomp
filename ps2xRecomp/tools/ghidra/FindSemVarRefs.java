// Diagnostic: find every reference to global address 0x3d4c40 -- the memory
// slot that holds the semaphore-3 ID read by FUN_00117520's WaitSema call
// (thread 2, one of the 3 confirmed-genuinely-dead worker threads this
// session) -- to find both the CreateSema-storing code and any potential
// SignalSema-issuing reader of the same slot.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindSemVarRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x3d4c40");
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(addr);
        int count = 0;
        while (it.hasNext() && count < 40) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println(String.format("XREF: %s@%s %s", r.getReferenceType(), from,
                    fn != null ? "(in " + fn.getName() + " entry=" + fn.getEntryPoint() + ")" : "(no fn)"));
            count++;
        }
        println("total (capped 40): " + count);

        // Also identify the function actually containing 0x11763c (the real
        // CreateSema call site per the live trace, which turned out to be
        // outside FUN_00117520's bounds).
        Address csAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x11763c");
        Function csFn = currentProgram.getFunctionManager().getFunctionContaining(csAddr);
        println("function containing 0x11763c: " + (csFn != null ? csFn.getName() + " (" + csFn.getEntryPoint() + "-" + csFn.getBody().getMaxAddress() + ")" : "none"));
    }
}
