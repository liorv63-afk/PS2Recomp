// Diagnostic: find every reference to the DMA-channel-base table at 0x390ca0
// (10 entries: VIF0/VIF1/GIF/IPU_FROM/IPU_TO/SIF0/SIF1/SIF2/SPR_FROM/SPR_TO),
// to locate the real generic "start DMA transfer on channel N" function, since
// FUN_001092b8 (which hardcodes each address via lui/ori) turned out to be a
// wait-for-idle sync barrier, not a kick function.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindDmaTableRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (long off = 0x390ca0L; off <= 0x390cc8L; off += 4) {
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
            StringBuilder refs = new StringBuilder();
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(addr);
            int count = 0;
            while (it.hasNext() && count < 20) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
                refs.append(r.getReferenceType()).append("@").append(from)
                    .append(fn != null ? "(in " + fn.getName() + " entry=" + fn.getEntryPoint() + ")" : "(no fn)")
                    .append(" ");
                count++;
            }
            println(String.format("XREFS_TO 0x%x: count>=%d refs=[%s]", off, count, refs.toString()));
        }
    }
}
