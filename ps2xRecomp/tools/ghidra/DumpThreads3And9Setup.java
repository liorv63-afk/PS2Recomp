// Diagnostic: identify and disassemble the functions containing the real
// CreateSema call sites for semId=66 (thread 3, caller pc 0x1642e0) and
// semId=205 (thread 9, caller pc 0x24f528), applying the same technique
// that successfully traced thread 2/semId=3's setup chain.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class DumpThreads3And9Setup extends GhidraScript {
    void dumpContaining(String label, String pcStr) throws Exception {
        Address pc = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(pcStr);
        Function fn = currentProgram.getFunctionManager().getFunctionContaining(pc);
        println("=== " + label + ": function containing " + pcStr + " ===");
        if (fn == null) {
            println("  none found");
            return;
        }
        Address start = fn.getEntryPoint();
        Address max = fn.getBody().getMaxAddress();
        println("  bounds: " + start + " - " + max);
        Address cur = start;
        int i = 0;
        while (cur != null && cur.compareTo(max) <= 0 && i < 160) {
            Instruction instr = currentProgram.getListing().getInstructionAt(cur);
            if (instr == null) break;
            println(String.format("0x%s: %s", cur, instr.toString()));
            cur = instr.getMaxAddress().next();
            i++;
        }
        println("  === callers of " + fn.getName() + " ===");
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
        dumpContaining("semId=66 (thread 3)", "0x1642e0");
        dumpContaining("semId=205 (thread 9)", "0x24f528");
    }
}
