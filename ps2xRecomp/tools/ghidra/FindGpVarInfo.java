// Diagnostic: resolve the symbol "iGpffff88b8" (a gp-relative global Ghidra's
// decompiler named, referenced by FUN_001614d0 -- thread 9's file-open call
// -- as a semaphore ID) to its real address, then find every reference to it
// (its CreateSema call site, and any other readers/writers).
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class FindGpVarInfo extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getSymbolIterator("*88b8*", true);
        boolean found = false;
        while (it.hasNext()) {
            Symbol s = it.next();
            String name = s.getName();
            if (!name.toLowerCase().contains("88b8")) continue;
            found = true;
            Address addr = s.getAddress();
            println("symbol: " + name + " @ " + addr);
            ReferenceIterator rit = currentProgram.getReferenceManager().getReferencesTo(addr);
            int c = 0;
            while (rit.hasNext() && c < 20) {
                Reference r = rit.next();
                Address from = r.getFromAddress();
                Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
                println("  ref: " + r.getReferenceType() + "@" + from + (fn != null ? " (in " + fn.getName() + ")" : " (no fn)"));
                c++;
            }
            println("  total refs shown: " + c);
        }
        if (!found) {
            println("no symbol matching *88b8* found");
        }
    }
}
