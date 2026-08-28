// Diagnostic: report instruction/function/reference state at a given address.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class InspectAddress extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] targets = { "0x10008c", "0x100090", "0x100094", "0x100098", "0x1000a0", "0x100200", "0x100210" };
        for (String t : targets) {
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(t);
            Instruction instr = currentProgram.getListing().getInstructionAt(addr);
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
            Function fnAt = currentProgram.getFunctionManager().getFunctionAt(addr);
            StringBuilder refs = new StringBuilder();
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(addr);
            int count = 0;
            while (it.hasNext() && count < 10) {
                Reference r = it.next();
                refs.append(r.getReferenceType()).append("@").append(r.getFromAddress()).append(" ");
                count++;
            }
            println(String.format("%s: instr=%s fnContaining=%s fnAt=%s refs=[%s]",
                t,
                instr != null ? instr.toString() : "null",
                fn != null ? fn.getName() + "(" + fn.getEntryPoint() + "-" + fn.getBody().getMaxAddress() + ")" : "null",
                fnAt != null ? fnAt.getName() : "null",
                refs.toString()));
        }
    }
}
