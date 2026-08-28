// Diagnostic: full disassembly of FUN_001175f8 (0x1175f8-0x1176e3) -- the
// real CreateSema call site for semaphore id=3 (thread 2's block) -- to see
// what happens to the returned ID and whether this same function (or a
// nearby one) also issues the corresponding SignalSema.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class DumpFun1175f8 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x1175f8");
        Function fn = currentProgram.getFunctionManager().getFunctionAt(start);
        println("bounds: " + (fn != null ? fn.getEntryPoint() + " - " + fn.getBody().getMaxAddress() : "NOT A FUNCTION"));
        Address cur = start;
        Address max = (fn != null) ? fn.getBody().getMaxAddress() : start.add(0x100);
        int i = 0;
        while (cur != null && cur.compareTo(max) <= 0 && i < 150) {
            Instruction instr = currentProgram.getListing().getInstructionAt(cur);
            if (instr == null) break;
            println(String.format("0x%s: %s", cur, instr.toString()));
            cur = instr.getMaxAddress().next();
            i++;
        }
        println("=== callers of FUN_001175f8 ===");
        ghidra.program.model.symbol.ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(start);
        int c = 0;
        while (it.hasNext() && c < 20) {
            ghidra.program.model.symbol.Reference r = it.next();
            Address from = r.getFromAddress();
            Function callerFn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("caller: " + r.getReferenceType() + "@" + from + (callerFn != null ? " (in " + callerFn.getName() + ")" : " (no fn)"));
            c++;
        }
    }
}
