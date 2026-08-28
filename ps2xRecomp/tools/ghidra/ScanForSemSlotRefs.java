// Diagnostic: full-.text scan for every instruction referencing the semaphore-3
// storage slot (absolute address 0x3d4c40) or the semaphore-66 storage slot
// (gp-relative offset -0x7754), across the ENTIRE binary -- not just code
// reached during a single live capture. Goal: find any SignalSema call site
// for these 2 semaphores that a 25s live run might never have exercised.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.Register;

public class ScanForSemSlotRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        AddressSetView textRange = currentProgram.getMemory().getExecuteSet();
        InstructionIterator it = currentProgram.getListing().getInstructions(textRange, true);

        int hits3 = 0;
        int hits66 = 0;
        int scanned = 0;

        while (it.hasNext()) {
            Instruction instr = it.next();
            scanned++;
            String mnem = instr.getMnemonicString();
            // Looking for lw/sw with a 16-bit signed offset operand.
            if (!(mnem.equals("lw") || mnem.equals("sw"))) {
                continue;
            }
            int numOps = instr.getNumOperands();
            for (int opIdx = 0; opIdx < numOps; opIdx++) {
                Object[] objs = instr.getOpObjects(opIdx);
                Scalar scalar = null;
                Register reg = null;
                for (Object o : objs) {
                    if (o instanceof Scalar) scalar = (Scalar) o;
                    if (o instanceof Register) reg = (Register) o;
                }
                if (scalar == null || reg == null) continue;
                long imm = scalar.getSignedValue();
                if (reg.getName().equals("gp") && imm == -0x7754L) {
                    Function fn = currentProgram.getFunctionManager().getFunctionContaining(instr.getAddress());
                    println(String.format("GP-7754 HIT: %s: %s (in %s)", instr.getAddress(), instr.toString(),
                            fn != null ? fn.getName() : "no fn"));
                    hits66++;
                }
                // absolute-address case: reg holds 0x3d0000-ish base, imm=0x4c40
                if (imm == 0x4c40L) {
                    Function fn = currentProgram.getFunctionManager().getFunctionContaining(instr.getAddress());
                    println(String.format("+0x4c40 HIT: %s: %s (in %s) [verify base reg=0x3d elsewhere]",
                            instr.getAddress(), instr.toString(), fn != null ? fn.getName() : "no fn"));
                    hits3++;
                }
            }
        }
        println(String.format("scanned=%d gp-7754hits=%d +0x4c40hits=%d", scanned, hits66, hits3));
    }
}
