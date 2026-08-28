// Diagnostic: disassemble the 4 functions found (via full-.text scan) to read
// or write semaphore-66's storage slot (gp-0x7754), to see whether any of them
// calls SignalSema (0x116840) or iSignalSema (0x116850) with it.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class DumpSem66Readers extends GhidraScript {
    void dumpFunc(String startStr) throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(startStr);
        Function fn = currentProgram.getFunctionManager().getFunctionAt(start);
        println("=== " + startStr + " bounds: " + (fn != null ? fn.getEntryPoint() + " - " + fn.getBody().getMaxAddress() : "NOT A FUNCTION") + " ===");
        Address cur = start;
        Address max = (fn != null) ? fn.getBody().getMaxAddress() : start.add(0x80);
        int i = 0;
        while (cur != null && cur.compareTo(max) <= 0 && i < 60) {
            Instruction instr = currentProgram.getListing().getInstructionAt(cur);
            if (instr == null) break;
            println(String.format("0x%s: %s", cur, instr.toString()));
            cur = instr.getMaxAddress().next();
            i++;
        }
    }

    @Override
    public void run() throws Exception {
        dumpFunc("0x163b50");
        dumpFunc("0x163c30");
        dumpFunc("0x163cc0");
        dumpFunc("0x1641c0");
    }
}
