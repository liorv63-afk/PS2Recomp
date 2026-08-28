#pragma once

#include "ps2_syscalls.h"

namespace ps2_syscalls
{
    void SifStopModule(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifLoadModule(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifInitRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifBindRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifCallRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifRegisterRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifCheckStatRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifSetRpcQueue(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifRemoveRpcQueue(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void SifRemoveRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void sceSifCallRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void sceSifSendCmd(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    void sceRpcGetPacket(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
    // Direct-call wrapper around SifInitRpc for binding to a JAL target (via a
    // game override) instead of a SYSCALL trap. SifInitRpc itself never touches
    // ctx->pc (correct for the syscall calling convention, where the caller's own
    // generated code continues linearly); this wrapper adds the explicit
    // "return to $ra" step that a direct-call replacement needs.
    void SifInitRpcDirectCallBridge(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime);
}
