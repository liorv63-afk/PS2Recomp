// Diagnostic: dump the 5-entry device-name pointer table at 0x395030
// (referenced by FUN_00162980's device-prefix matcher) and read each
// pointed-to string, to confirm device index 0 is "cdrom0" (or similar).
// @category PS2Recomp

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class DumpDeviceTable extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        for (int i = 0; i < 5; i++) {
            long tableEntryAddr = 0x395030L + (i * 4L);
            Address tableEntryAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(tableEntryAddr);
            int strPtr = mem.getInt(tableEntryAddress);
            StringBuilder sb = new StringBuilder();
            try {
                Address strAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(strPtr & 0xFFFFFFFFL);
                for (int j = 0; j < 32; j++) {
                    byte b = mem.getByte(strAddr.add(j));
                    if (b == 0) break;
                    sb.append((char) (b & 0xFF));
                }
            } catch (Exception e) {
                sb.append("<unreadable>");
            }
            println(String.format("device[%d]: strPtr=0x%x -> \"%s\"", i, strPtr, sb.toString()));
        }
    }
}
