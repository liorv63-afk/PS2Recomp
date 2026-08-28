// Diagnostic: decompile one or more functions to C-like pseudocode via
// Ghidra's DecompInterface, for much faster reading than raw disassembly when
// tracing complex forward control flow (e.g. "what happens after a successful
// SIF bind"). Pass target addresses in the `targets` array below.
// @category PS2Recomp

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileFunc extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] targets = { "0x12ac90", "0x12a670" };

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        for (String t : targets) {
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(t);
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
            println("=== decompiling function containing " + t + " (" + (fn != null ? fn.getName() + " entry=" + fn.getEntryPoint() : "no fn") + ") ===");
            if (fn == null) {
                println("  no function at this address");
                continue;
            }
            DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
            if (res != null && res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("  decompile failed: " + (res != null ? res.getErrorMessage() : "null result"));
            }
        }
        decomp.dispose();
    }
}
