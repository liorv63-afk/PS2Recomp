// Diagnostic: dump the data table around 0x390ca4 (found to contain the literal
// 0x10009000/VIF1-CHCR constant) as an array of uint32 words, and disassemble the
// first part of FUN_001092b8 (0x1092b8) to see whether/how it indexes into it.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class DumpDmaTableAndFunc extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();

        println("=== data table around 0x390c80-0x390d00 ===");
        for (long off = 0x390c80L; off <= 0x390d00L; off += 4) {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
            try {
                int v = mem.getInt(a);
                println(String.format("0x%x: 0x%08x", off, v));
            } catch (Exception e) {
                println(String.format("0x%x: <unreadable>", off));
            }
        }

        println("=== disassembly of FUN_001092b8 (first 80 instrs) ===");
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x1092b8");
        Address cur = start;
        for (int i = 0; i < 80; i++) {
            Instruction instr = currentProgram.getListing().getInstructionAt(cur);
            if (instr == null) break;
            println(String.format("0x%s: %s", cur, instr.toString()));
            cur = instr.getMaxAddress().next();
            if (cur == null) break;
        }
    }
}
