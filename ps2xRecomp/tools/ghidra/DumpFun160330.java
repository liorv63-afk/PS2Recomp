// Diagnostic: full disassembly of FUN_00160330 -- called every tick from the
// main per-frame dispatcher (FUN_001690e0) and one of the 8 callers of
// FUN_00109f98 (get-DMA-channel-base-by-index). Checking whether it requests
// VIF1 (index 1) and whether it actually sets MADR/QWC/CHCR-STR afterward.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class DumpFun160330 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x160330");
        Function fn = currentProgram.getFunctionManager().getFunctionAt(start);
        println("bounds: " + (fn != null ? fn.getEntryPoint() + " - " + fn.getBody().getMaxAddress() : "NOT A FUNCTION"));
        Address cur = start;
        Address max = (fn != null) ? fn.getBody().getMaxAddress() : start.add(0x200);
        int i = 0;
        while (cur != null && cur.compareTo(max) <= 0 && i < 200) {
            Instruction instr = currentProgram.getListing().getInstructionAt(cur);
            if (instr == null) break;
            println(String.format("0x%s: %s", cur, instr.toString()));
            cur = instr.getMaxAddress().next();
            i++;
        }
    }
}
