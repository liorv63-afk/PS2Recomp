// Diagnostic: disassemble FUN_00109f98 and FUN_00109fc0 (both found referencing
// the DMA-channel-base table at 0x390ca0) in full, and list every caller (XREF)
// of each, to identify the real generic "start DMA transfer on channel N"
// function and see who calls it (and how often) during the game's boot path.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class DumpDmaKickFuncs extends GhidraScript {
    void dumpFunc(String name, String startStr) throws Exception {
        println("=== " + name + " disassembly ===");
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(startStr);
        Function fn = currentProgram.getFunctionManager().getFunctionAt(start);
        if (fn == null) {
            println("  (no function found at " + startStr + ")");
            return;
        }
        println("  bounds: " + fn.getEntryPoint() + " - " + fn.getBody().getMaxAddress());
        Address cur = start;
        Address max = fn.getBody().getMaxAddress();
        int i = 0;
        while (cur != null && cur.compareTo(max) <= 0 && i < 120) {
            Instruction instr = currentProgram.getListing().getInstructionAt(cur);
            if (instr == null) break;
            println(String.format("0x%s: %s", cur, instr.toString()));
            cur = instr.getMaxAddress().next();
            i++;
        }
        println("  === callers of " + name + " ===");
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(start);
        int count = 0;
        while (it.hasNext() && count < 30) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Function callerFn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  caller: " + r.getReferenceType() + "@" + from +
                    (callerFn != null ? " (in " + callerFn.getName() + ")" : " (no fn)"));
            count++;
        }
        println("  total callers (capped 30): " + count);
    }

    @Override
    public void run() throws Exception {
        dumpFunc("FUN_00109f98", "0x109f98");
        dumpFunc("FUN_00109fc0", "0x109fc0");
    }
}
