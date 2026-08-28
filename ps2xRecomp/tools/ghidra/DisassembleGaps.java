// Force-disassembles undefined 4-byte-aligned addresses in executable memory blocks,
// then re-runs auto-analysis so function boundaries get detected over the new code.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class DisassembleGaps extends GhidraScript {
    @Override
    public void run() throws Exception {
        int disassembledCount = 0;
        int failedCount = 0;

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block == null || !block.isExecute() || !block.isInitialized()) {
                continue;
            }

            Address addr = block.getStart();
            Address end = block.getEnd();

            while (addr != null && addr.compareTo(end) <= 0 && !monitor.isCancelled()) {
                Instruction instr = currentProgram.getListing().getInstructionAt(addr);
                Data data = currentProgram.getListing().getDefinedDataAt(addr);

                if (instr == null && data == null) {
                    boolean ok = disassemble(addr);
                    if (ok) {
                        disassembledCount++;
                    } else {
                        failedCount++;
                    }
                }

                try {
                    addr = addr.add(4);
                } catch (Exception e) {
                    break;
                }
            }
        }

        println(String.format("DisassembleGaps: disassembled %d new instructions, %d addresses failed to disassemble.",
            disassembledCount, failedCount));

        println("DisassembleGaps: re-running auto-analysis over the whole program...");
        analyzeAll(currentProgram);
        println("DisassembleGaps: auto-analysis complete.");
    }
}
