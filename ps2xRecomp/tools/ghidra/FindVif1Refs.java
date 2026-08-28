// Diagnostic: report every reference (code xref, constant-propagated address use,
// or otherwise) to VIF1's DMA register block base (0x10009000) and its known
// sub-registers (CHCR/MADR/QWC/TADR), to find what guest code, if any, actually
// configures/kicks VIF1 DMA -- static XREF pass, not live-tracing.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindVif1Refs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] targets = {
            "0x10009000", // VIF1 CHCR
            "0x10009010", // VIF1 MADR
            "0x10009020", // VIF1 QWC
            "0x10009030", // VIF1 TADR
            "0x10009040", // VIF1 ASR0
            "0x10009050", // VIF1 ASR1
        };
        for (String t : targets) {
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(t);
            StringBuilder refs = new StringBuilder();
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(addr);
            int count = 0;
            while (it.hasNext() && count < 40) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
                refs.append(r.getReferenceType()).append("@").append(from)
                    .append(fn != null ? "(in " + fn.getName() + ")" : "(no fn)")
                    .append(" ");
                count++;
            }
            println(String.format("XREFS_TO %s: count>=%d refs=[%s]", t, count, refs.toString()));
        }
    }
}
