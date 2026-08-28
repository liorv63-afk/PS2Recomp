// Diagnostic: dump raw bytes and try explicit disassembly at 0x10008c.
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class InspectBytes extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x10008c");
        byte[] bytes = new byte[16];
        currentProgram.getMemory().getBytes(addr, bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b));
        }
        println("Bytes at 0x10008c: " + sb.toString());

        InstructionIterator before = currentProgram.getListing().getInstructions(
            currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x100080"), true);
        int n = 0;
        while (before.hasNext() && n < 8) {
            Instruction i = before.next();
            println("  " + i.getAddress() + ": " + i.toString() + "  bytes=" + i.getBytes().length);
            n++;
        }

        try {
            Instruction result = disassemble(addr) ? currentProgram.getListing().getInstructionAt(addr) : null;
            println("disassemble() result at 0x10008c: " + (result != null ? result.toString() : "FAILED"));
        } catch (Exception e) {
            println("disassemble() threw: " + e);
        }
    }
}
