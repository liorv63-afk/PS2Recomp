// Diagnostic: disassemble FUN_00117520 in full (creates semaphore id=3, one of
// the 3 confirmed-genuinely-dead worker-thread semaphores this session), to see
// what happens to the returned semaphore ID -- is it stored to a global address
// that some other function could read and later call SignalSema with?
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class DumpFun117520 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x117520");
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
    }
}
