#include "game_overrides.h"
#include "ps2_syscalls.h"
#include <atomic>
#include <iostream>

namespace ps2_syscalls
{
    // EXPERIMENTAL (see project memory, 2026-08-27): func_165B90/func_165C00
    // (address 0x165b90-0x165e9c) is DQ8's own custom dispatch-queue wait
    // primitive -- FUN_001690e0 (the boot orchestrator) makes a single
    // synchronous call to func_165B90(entity=0x3F17B0), which busy-polls a
    // dispatch field (entity+4, offset+0x14) on the sub-object at 0x3F17B4,
    // waiting for it to become nonzero. Exhaustively confirmed (2026-08-26,
    // 25-minute live memory watchpoint; 2026-08-27, a full literal-address
    // sweep of all ~40,800 generated files for the exact lui-0x3F/addiu-
    // 0x17B0 construction, covering all 23 real references to this base
    // address) that NOTHING in DQ8's own reachable code, nor any currently
    // created thread (1/5/6/7/plus four more identified 2026-08-27), ever
    // writes that field -- this is architecturally the same class of problem
    // already solved for func_119DE0 (DQ8's inlined SifInitRpc, see below):
    // a statically-linked wait for an external/IOP-driven signal our runtime
    // doesn't simulate. Bridges over the ENTIRE wait by returning to the
    // caller immediately, exactly as SifInitRpcDirectCallBridge does for
    // func_119DE0, to test whether letting the boot orchestrator proceed
    // past this specific point unblocks further progress.
    void Dq8EntityWaitBridge(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static std::atomic<uint32_t> s_hitCount{0u};
        const uint32_t n = s_hitCount.fetch_add(1u, std::memory_order_relaxed);
        if (n < 20u)
        {
            std::cerr << "[dq8-entity-wait-bridge] #" << std::dec << n
                       << " bypassing func_165B90 wait, a0=0x" << std::hex << getRegU32(ctx, 4)
                       << std::dec << std::endl;
        }
        const uint32_t returnAddr = getRegU32(ctx, 31);
        ctx->pc = returnAddr;
    }
}

namespace
{
    void applyDq8Overrides(PS2Runtime &runtime)
    {
        // DQ8 statically links PS2SDK's own libkernel sceSifInitRpc() implementation
        // at 0x119de0 (called from 13 sites with no arguments -- an idempotent
        // "ensure SIF RPC is ready" helper). Confirmed by matching the exact command
        // IDs it registers handlers for against real PS2SDK source
        // (common/include/sifcmd-common.h): 0x80000008/9/A/C are precisely
        // SIF_CMD_RPC_END/RPC_BIND/RPC_CALL/RPC_RDATA. It then busy-waits on a
        // guest-memory completion flag that only the IOP side of a real SIF RPC
        // handshake would ever set -- which our runtime doesn't simulate, so the
        // wait never ends.
        //
        // Our own ps2xRuntime already has a complete, synchronous, idempotent
        // SifInitRpc implementation (ps2_syscalls::SifInitRpc, RPC.cpp) used
        // elsewhere via the syscall path. Replace DQ8's inlined copy outright with
        // ours (via the SifInitRpcDirectCallBridge wrapper, which adds the explicit
        // "return to $ra" a direct-call replacement needs) rather than trying to
        // bridge its internal guest-memory table -- this sidesteps needing to
        // understand or replicate that table at all.
        const bool bound = ps2_game_overrides::bindAddressHandler(runtime, 0x119de0u, "SifInitRpcDirectCallBridge");
        std::cerr << "[dq8-override] bind 0x119de0 -> SifInitRpcDirectCallBridge: " << bound << std::endl;

        // EXPERIMENTAL (see project memory, 2026-08-27): see Dq8EntityWaitBridge
        // above for the full rationale. Bypasses FUN_001690e0's (the boot
        // orchestrator's) single blocking call to func_165B90(0x3F17B0), the
        // central 2026-08-26 boot-blocker, to test whether it's safe to treat
        // this wait as already-satisfied.
        const bool boundEntityWait = ps2_game_overrides::bindAddressHandler(runtime, 0x165b90u, "Dq8EntityWaitBridge");
        std::cerr << "[dq8-override] bind 0x165b90 -> Dq8EntityWaitBridge: " << boundEntityWait << std::endl;
    }
}

PS2_REGISTER_GAME_OVERRIDE("dq8-us", "SLUS_212.07", 0u, 0u, &applyDq8Overrides)

// Force-link hook: ps2_runtime is a static library, and nothing else references
// any symbol in this translation unit (self-registration via the static
// AutoRegister object above is the only side effect). Without an actual
// caller->callee reference, the linker silently drops this whole .obj from the
// final executable and the registration constructor never runs. Called once
// from ps2_runtime.cpp to force inclusion.
extern "C" void ps2x_force_link_dq8_overrides()
{
}
