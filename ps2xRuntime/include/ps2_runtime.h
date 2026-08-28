#ifndef PS2_RUNTIME_H
#define PS2_RUNTIME_H

#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(USE_SSE2NEON)
#include "sse2neon.h"
#else
#include <immintrin.h> // For SSE/AVX instructions
#include <smmintrin.h> // For SSE4.1 instructions
#endif
#include <atomic>
#include <array>
#include <mutex>
#include <filesystem>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "ps2_log.h"
#include "runtime/ps2_address.h"
#include "runtime/gs/ps2_gif_arbiter.h"
#include "runtime/ps2_memory.h"
#include "runtime/gs/gs_frontend.h"
#include "runtime/ps2_vu1.h"
#include "runtime/ps2_audio.h"
#include "runtime/ps2_pad.h"
#include "ps2x/iop/iop_types.h"
#include "ps2_disc_fs.h"

namespace ps2x::iop
{
    class IopSubsystem;
}

class PS2IopHostAdapter;
class PS2IopTransport;
class EeScheduler;
struct EeEvent;

enum PS2Exception
{
    EXCEPTION_TLB_REFILL = 0x02,          // TLB refill/load exception
    EXCEPTION_ADDRESS_ERROR_LOAD = 0x04,  // Address error on load
    EXCEPTION_ADDRESS_ERROR_STORE = 0x05, // Address error on store
    EXCEPTION_SYSCALL = 0x08,             // SYSCALL instruction
    EXCEPTION_BREAKPOINT = 0x09,          // BREAK instruction
    EXCEPTION_RESERVED_INSTRUCTION = 0x0A,
    EXCEPTION_INTEGER_OVERFLOW = 0x0C, // From MIPS spec
    EXCEPTION_TRAP = 0x0D,             // Trap instruction condition met
};

// PS2 CPU context (R5900)
struct alignas(16) R5900Context
{
    // General Purpose Registers (128-bit)
    __m128i r[32]; // Main registers

    // Control registers
    uint32_t pc;         // Program counter
    uint64_t insn_count; // Instruction counter
    uint64_t hi, lo;     // HI/LO registers for mult/div results
    uint64_t hi1, lo1;   // Secondary HI/LO registers for MULT1/DIV1
    uint32_t sa;         // Shift amount register

    // VU0 registers (when used in macro mode)
    __m128 vu0_vf[32];        // VU0 vector float registers
    uint16_t vi[16];          // VU0 vector integer registers
    float vu0_q;              // VU0 Q register (quotient)
    float vu0_p;              // VU0 P register (EFU result)
    float vu0_i;              // VU0 I register (integer value)
    __m128 vu0_r;             // VU0 R register
    __m128 vu0_acc;           // VU0 ACC accumulator register
    uint16_t vu0_status;      // VU0 status register
    uint32_t vu0_mac_flags;   // VU0 MAC flags
    uint32_t vu0_clip_flags;  // VU0 clipping flags
    uint32_t vu0_clip_flags2; // VU0 clipping flags
    uint32_t vu0_cmsar0;      // VU0 microprogram start address
    uint32_t vu0_cmsar1;      // VU0 microprogram start address
    uint32_t vu0_cmsar2;      // VU0 microprogram start address
    uint32_t vu0_cmsar3;      // VU0 microprogram start address
    uint32_t vu0_vpu_stat;
    uint32_t vu0_vpu_stat2; // extra VPU status (used by CR_VPU_STAT2)
    uint32_t vu0_vpu_stat3; // extra VPU status 3
    uint32_t vu0_vpu_stat4; // extra VPU status 4
    uint32_t vu0_tpc;       // TPC (VU0 PC)
    uint32_t vu0_tpc2;      // second TPC
    uint32_t vu0_fbrst;     // VIF/VU reset register
    uint32_t vu0_fbrst2;    // FBRST2
    uint32_t vu0_fbrst3;    // FBRST3
    uint32_t vu0_fbrst4;    // FBRST4
    uint32_t vu0_itop;
    uint32_t vu0_top;
    uint32_t vu0_info;
    uint32_t vu0_xitop; // VU0 XITOP - input ITOP for VIF/VU sync
    uint32_t vu0_pc;

    float vu0_cf[4]; // VU0 FMAC control floating-point registers

    // COP0 System control registers
    uint32_t cop0_index;
    uint32_t cop0_random;
    uint32_t cop0_entrylo0;
    uint32_t cop0_entrylo1;
    uint32_t cop0_context;
    uint32_t cop0_pagemask;
    uint32_t cop0_wired;
    uint32_t cop0_badvaddr;
    uint32_t cop0_count;
    uint32_t cop0_entryhi;
    uint32_t cop0_compare;
    uint32_t cop0_status;
    uint32_t cop0_cause;
    uint32_t cop0_epc;
    uint32_t cop0_prid;
    uint32_t cop0_config;
    uint32_t cop0_badpaddr;
    uint32_t cop0_debug;
    uint32_t cop0_perf;
    uint32_t cop0_taglo;
    uint32_t cop0_taghi;
    uint32_t cop0_errorepc;

    // LL/SC reservation state (not part of COP0 Status bits).
    uint32_t llbit;
    uint32_t lladdr;

    // Delay slot state tracking
    bool in_delay_slot;
    uint32_t branch_pc;

    // COP2 control registers (VU0 integer + control)
    uint32_t cop2_ccr[32];

    // FPU registers (COP1)
    float f[32];
    float f_acc;    // FPU accumulator
    uint32_t fcr31; // Control/status register

    R5900Context()
    {
        std::memset(this, 0, sizeof(*this));

        // Initialize VU0 registers
        vu0_q = 1.0f; // Q register usually initialized to 1.0

        // Reset COP0 registers
        cop0_random = 47; // Start at maximum value
        // Status as the EE kernel leaves it at handoff. IE (bit 0) and EIE
        // (bit 16) are separate enables and guest code reads both; libkernel's
        // StartThread refuses to run while IE is clear.
        cop0_status = 0x00010001; // EIE | IE
        cop0_prid = 0x00002e20; // CPU ID for R5900

        in_delay_slot = false;
        branch_pc = 0;
    }

    void dump() const
    {
        std::ios_base::fmtflags flags = std::cout.flags();
        std::cout << std::hex << std::setfill('0');
        std::cout << "--- R5900 Context Dump ---\n";
        std::cout << "PC: 0x" << std::setw(8) << pc << "\n";
        std::cout << "HI: 0x" << std::setw(8) << hi << " LO: 0x" << std::setw(8) << lo << "\n";
        std::cout << "HI1:0x" << std::setw(8) << hi1 << " LO1:0x" << std::setw(8) << lo1 << "\n";
        std::cout << "SA: 0x" << std::setw(8) << sa << "\n";
        for (int i = 0; i < 32; ++i)
        {
            std::cout << "R" << std::setw(2) << std::dec << i << ": 0x" << std::hex
                      << std::setw(8) << static_cast<uint32_t>(_mm_extract_epi32(r[i], 3))
                      << std::setw(8) << static_cast<uint32_t>(_mm_extract_epi32(r[i], 2)) << "_"
                      << std::setw(8) << static_cast<uint32_t>(_mm_extract_epi32(r[i], 1))
                      << std::setw(8) << static_cast<uint32_t>(_mm_extract_epi32(r[i], 0)) << "\n";
        }
        std::cout << "Status: 0x" << std::setw(8) << cop0_status
                  << " Cause: 0x" << std::setw(8) << cop0_cause
                  << " EPC: 0x" << std::setw(8) << cop0_epc << "\n";
        std::cout << "--- End Context Dump ---\n";
        std::cout.flags(flags); // Restore format flags
    }

    ~R5900Context() = default;
};

inline uint32_t getRegU32(const R5900Context *ctx, int reg)
{
    // Check if reg is valid (0-31)
    if (reg < 0 || reg > 31)
        return 0;
    if (reg == 0)
        return 0;
    return static_cast<uint32_t>(_mm_extract_epi32(ctx->r[reg], 0));
}

inline void setReturnU32(R5900Context *ctx, uint32_t value)
{
    // R5900 sign-extends 32-bit results into 64-bit GPR, even for unsigned values.
    ctx->r[2] = _mm_set_epi64x(0, static_cast<int64_t>(static_cast<int32_t>(value))); // $v0
}

inline void setReturnS32(R5900Context *ctx, int32_t value)
{
    // Signed 32-bit return should be sign-extended when observed as 64-bit.
    ctx->r[2] = _mm_set_epi64x(0, static_cast<int64_t>(value)); // $v0
}

inline void setReturnU64(R5900Context *ctx, uint64_t value)
{
    // Keep both conventions: full 64-bit value in $v0 and high 32-bit in $v1.
    ctx->r[2] = _mm_set_epi64x(0, static_cast<int64_t>(value));
    ctx->r[3] = _mm_set_epi64x(0, static_cast<int64_t>(static_cast<uint32_t>(value >> 32)));
}

inline constexpr uint32_t PS2_PATH_WATCH_ADDR = 0x01EFFFA0u;
inline constexpr uint32_t PS2_PATH_WATCH_BYTES = 0x200u;

inline uint32_t ps2PathWatchPhysAddr()
{
    return PS2_PATH_WATCH_ADDR & PS2_RAM_MASK;
}

inline uint8_t ps2PathWatchExtractByteFromWrite(uint32_t writeAddr, uint32_t watchAddr, uint64_t valueLo, uint64_t valueHi)
{
    const uint32_t byteIndex = watchAddr - writeAddr;
    if (byteIndex < 8u)
    {
        return static_cast<uint8_t>((valueLo >> (byteIndex * 8u)) & 0xFFu);
    }
    return static_cast<uint8_t>((valueHi >> ((byteIndex - 8u) * 8u)) & 0xFFu);
}

// DIAGNOSTIC (2026-08-28): kOpenSendBuf (0x3D7040, FUN_0011bba8's own fixed
// scratch buffer for the file-open SIF call) has no per-call isolation --
// confirmed live that after enough call volume, some other operation
// overwrites it before an in-flight open's data is read back, corrupting
// the reply and permanently hanging the caller (see project memory,
// 2026-08-28). Rather than logging every write (this buffer is touched
// extremely often during normal operation -- would flood the log long
// before reaching the rare corruption), keep a small ring buffer of the
// most recent writes; ps2_runtime.cpp dumps it only when it detects the
// corrupted-read symptom, showing exactly what wrote here immediately
// before the failure.
struct KOpenSendBufWriteRecord
{
    uint32_t addr = 0u;
    uint32_t size = 0u;
    uint64_t valueLo = 0u;
    uint32_t pc = 0u;
};
inline std::array<KOpenSendBufWriteRecord, 32> g_kOpenSendBufWriteHistory{};
inline std::atomic<uint32_t> g_kOpenSendBufWriteHistoryIndex{0u};

// REAL FIX (2026-08-28): the write-history ring buffer above proved
// kOpenSendBuf+0x0 (the semaphore id FUN_0011bba8 wants signaled once its
// SIF call completes) gets legitimately written once by FUN_0011bba8 itself
// (pc in its own 0x11bba8-0x11be38 range), then LATER overwritten by
// func_11A768's own internal packet-construction machinery (pc in the
// 0x119xxx-0x11axxx range, reusing the exact same fixed bufPtr=0x3d7000
// address, which kOpenSendBuf is just +0x40 into) before our SIF-reply hook
// ever gets to read it -- by the time we read, we get whatever THAT other
// machinery left behind, not FUN_0011bba8's real value. Caching the value
// at the moment FUN_0011bba8 itself writes it (identified by pc range, not
// by re-deriving it from the same racy shared memory) sidesteps the race
// entirely for this one critical field.
inline std::atomic<uint32_t> g_lastGoodOpenSemToSignal{0u};
// Same race, same fix, for the destPtr field (kOpenSendBuf+0x4) -- confirmed
// live in the same write-history dump: correctly written 0x1fff9b0 at
// pc=0x11bd24, then clobbered to 0 at pc=0x119ac4 before our hook read it.
inline std::atomic<uint32_t> g_lastGoodOpenDestPtr{0u};

inline void ps2TraceGuestWrite(uint8_t *rdram,
                               uint32_t guestAddr,
                               uint32_t size,
                               uint64_t valueLo,
                               uint64_t valueHi,
                               const char *op,
                               const R5900Context *ctx)
{
    (void)rdram;
    (void)size;
    (void)valueLo;
    (void)valueHi;
    (void)op;

    // Temporary watchpoint: log any write touching the DQ8 IOP-ready poll flag
    // at 0x3d5740 (see project memory) so we can see what, if anything, ever
    // sets it and from where.
    if (guestAddr >= 0x3d5740u && guestAddr < 0x3d5750u)
    {
        static std::atomic<uint32_t> s_watchLogCount{0u};
        if (s_watchLogCount.fetch_add(1u, std::memory_order_relaxed) < 100u)
        {
            std::cerr << "[watch-3d5740] addr=0x" << std::hex << guestAddr
                      << " size=" << std::dec << size
                      << " valueLo=0x" << std::hex << valueLo
                      << " pc=0x" << (ctx ? ctx->pc : 0u)
                      << std::dec << std::endl;
        }
    }
    // Temporary watchpoint (2026-08-27): what writes 0x3D8768 to the value
    // 0x8 observed at func_11B8B0's check-time? Known writers so far:
    // FUN_0011b940 zeroes it (via func_132848, a memset-style call) as part
    // of a filesystem close/reset; nothing else was found via static
    // literal-address search (lui 0x3D/0x3E + matching addiu), meaning the
    // real writer likely uses $gp-relative addressing or a long-lived cached
    // base register this session's grep technique can't find statically.
    if (guestAddr >= 0x3d8760u && guestAddr < 0x3d8780u)
    {
        static std::atomic<uint32_t> s_watch3d8768LogCount{0u};
        if (s_watch3d8768LogCount.fetch_add(1u, std::memory_order_relaxed) < 200u)
        {
            std::cerr << "[watch-3d8768] addr=0x" << std::hex << guestAddr
                      << " size=" << std::dec << size
                      << " valueLo=0x" << std::hex << valueLo
                      << " pc=0x" << (ctx ? ctx->pc : 0u)
                      // s0 (reg16) got REPURPOSED partway through func_11B6A8
                      // (confirmed: client+0/+4 don't match the observed 0x8
                      // -- the same register-liveness trap this session hit
                      // before in a different function). Logging s0's LIVE
                      // value here (at write-time) to find its real source
                      // address, since static tracing already got this wrong
                      // once.
                      << " s0(reg16)=0x" << (ctx ? getRegU32(ctx, 16) : 0u)
                      << std::dec << std::endl;
        }
    }
    // Temporary watchpoint: log any write touching the fixed-size pool
    // descriptor at 0x3d6fc0 (list base at +4, slot count at +8) that
    // FUN_0012ae98's retry loop keeps finding uninitialized (see project
    // memory, 2026-08-25). Widened past +0x20 to catch nearby struct writes.
    if (guestAddr >= 0x3d6fc0u && guestAddr < 0x3d6fe0u)
    {
        static std::atomic<uint32_t> s_watchPoolLogCount{0u};
        if (s_watchPoolLogCount.fetch_add(1u, std::memory_order_relaxed) < 100u)
        {
            std::cerr << "[watch-3d6fc0] addr=0x" << std::hex << guestAddr
                      << " size=" << std::dec << size
                      << " valueLo=0x" << std::hex << valueLo
                      << " pc=0x" << (ctx ? ctx->pc : 0u)
                      << std::dec << std::endl;
        }
    }
    // Temporary watchpoint: catch any write ANYWHERE in guest memory whose
    // *value* (not address) falls within the 0x3d6fc0 pool's own struct
    // range. This is looking for an indirect chain -- e.g. some other code
    // storing a pointer TO this pool into a registry/table elsewhere -- that
    // a pure address-pattern search (see project memory, 2026-08-25) cannot
    // find, since the pool's address may never appear as a literal immediate
    // anywhere in the instruction stream if it's only ever produced by
    // pointer arithmetic on some other already-computed base.
    {
        const uint32_t lo32 = static_cast<uint32_t>(valueLo);
        if (lo32 >= 0x3d6fc0u && lo32 < 0x3d6fe0u)
        {
            static std::atomic<uint32_t> s_watchPoolValueLogCount{0u};
            if (s_watchPoolValueLogCount.fetch_add(1u, std::memory_order_relaxed) < 100u)
            {
                std::cerr << "[watch-value-3d6fc0] wroteAddr=0x" << std::hex << guestAddr
                          << " size=" << std::dec << size
                          << " value=0x" << std::hex << lo32
                          << " pc=0x" << (ctx ? ctx->pc : 0u)
                          << std::dec << std::endl;
            }
        }
    }
    // Temporary watchpoint (see project memory, 2026-08-26): FUN_001690e0
    // (the boot orchestrator) makes a blocking call into an entity/queue
    // processor for the struct at 0x3F17B0 (checked field at +4+0x14 =
    // 0x3F17C8) and never returns because that field never becomes
    // nonzero -- this is the current single blocking point for the whole
    // boot sequence. Log any write touching this struct to find whoever,
    // if anyone, is supposed to populate it.
    if (guestAddr >= 0x3f17b0u && guestAddr < 0x3f17e0u)
    {
        // The one write that actually matters: the dispatch field at
        // 0x3f17c8 becoming nonzero. Log this unconditionally, uncapped --
        // it should be rare/never, so there's no volume risk, and missing
        // it due to a shared cap being exhausted by routine reset noise
        // (confirmed happening in the capped version) would defeat the
        // whole point of this watchpoint.
        if (guestAddr == 0x3f17c8u && valueLo != 0u)
        {
            std::cerr << "[watch-3f17c8-NONZERO] size=" << std::dec << size
                      << " valueLo=0x" << std::hex << valueLo
                      << " pc=0x" << (ctx ? ctx->pc : 0u)
                      << std::dec << std::endl;
        }
        static std::atomic<uint32_t> s_watchEntityLogCount{0u};
        static std::atomic<int64_t> s_watchEntityLastLogMs{0};
        const auto nowMsEntity = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count();
        int64_t lastEntity = s_watchEntityLastLogMs.load(std::memory_order_relaxed);
        if (nowMsEntity - lastEntity >= 200 &&
            s_watchEntityLastLogMs.compare_exchange_strong(lastEntity, nowMsEntity, std::memory_order_relaxed))
        {
            const uint32_t n = s_watchEntityLogCount.fetch_add(1u, std::memory_order_relaxed);
            std::cerr << "[watch-3f17b0] #" << n << " addr=0x" << std::hex << guestAddr
                      << " size=" << std::dec << size
                      << " valueLo=0x" << std::hex << valueLo
                      << " pc=0x" << (ctx ? ctx->pc : 0u)
                      << std::dec << std::endl;
        }
    }
    // Temporary watchpoint (2026-08-28): FUN_00165570 calls FUN_00165c00
    // (DQ8's own token/script dispatcher) with a1(cursor)/a2 read from the
    // SAME entity struct's own fields at +0xB4/+0xB8 (entity base 0x3f17b0,
    // so 0x3f1864/0x3f1868) -- confirmed live both are always 0 (a null
    // cursor), which is why the dispatcher only ever sees an empty/idle
    // state and never processes real script content. Neither field falls
    // within the existing 0x3f17b0-0x3f17e0 watch range above. Does ANYTHING
    // ever write a real (nonzero) value here?
    if (guestAddr >= 0x3f1860u && guestAddr < 0x3f1870u)
    {
        static std::atomic<uint32_t> s_watchCursorLogCount{0u};
        if (s_watchCursorLogCount.fetch_add(1u, std::memory_order_relaxed) < 20000u)
        {
            std::cerr << "[watch-3f1864-cursor] addr=0x" << std::hex << guestAddr
                      << " size=" << std::dec << size
                      << " valueLo=0x" << std::hex << valueLo
                      << " pc=0x" << (ctx ? ctx->pc : 0u)
                      << std::dec << std::endl;
        }
    }
    // Temporary watchpoint (2026-08-27): does ANYTHING ever write into the
    // 32-slot/16-byte-stride file-descriptor table at 0x3D8540-0x3D8740
    // (confirmed shared between FUN_0011bba8's open, func_11AF88's slot
    // allocator, and FUN_0011bfb0/func_11B100's read-side lookup)? Slot
    // field +0 was observed as 0 at read time, producing a nonsensical
    // block-count computation downstream -- this checks whether ANY guest
    // code ever populates it (or any other slot field), before assuming a
    // host-side fix is required.
    if (guestAddr >= 0x3d8540u && guestAddr < 0x3d8740u)
    {
        static std::atomic<uint32_t> s_watchFdTableLogCount{0u};
        if (s_watchFdTableLogCount.fetch_add(1u, std::memory_order_relaxed) < 200u)
        {
            std::cerr << "[watch-fdtable] addr=0x" << std::hex << guestAddr
                      << " slotOffset=0x" << ((guestAddr - 0x3d8540u) % 0x10u)
                      << " size=" << std::dec << size
                      << " valueLo=0x" << std::hex << valueLo
                      << " pc=0x" << (ctx ? ctx->pc : 0u)
                      << std::dec << std::endl;
        }
    }
    // kOpenSendBuf write-history ring buffer (see struct comment above) --
    // covers the full 0x418-byte send buffer (the actual open payload can
    // be that large), not just the small header fields, since the
    // corruption's exact shape isn't known in advance.
    if (guestAddr >= 0x3d7040u && guestAddr < 0x3d7040u + 0x418u)
    {
        const uint32_t idx = g_kOpenSendBufWriteHistoryIndex.fetch_add(1u, std::memory_order_relaxed) %
                              static_cast<uint32_t>(g_kOpenSendBufWriteHistory.size());
        g_kOpenSendBufWriteHistory[idx] = KOpenSendBufWriteRecord{guestAddr, size, valueLo, ctx ? ctx->pc : 0u};

        // Cache the semaphore id the moment FUN_0011bba8 itself writes it
        // (pc within its own function body), before func_11A768's internal
        // machinery gets a chance to overwrite the same bytes.
        if (ctx && ctx->pc >= 0x11bba8u && ctx->pc < 0x11be38u)
        {
            if (guestAddr == 0x3d7040u && size == 4u)
            {
                g_lastGoodOpenSemToSignal.store(static_cast<uint32_t>(valueLo), std::memory_order_relaxed);
            }
            else if (guestAddr == 0x3d7044u && size == 4u)
            {
                g_lastGoodOpenDestPtr.store(static_cast<uint32_t>(valueLo), std::memory_order_relaxed);
            }
        }
    }
    // Temporary watchpoint (2026-08-27): trace the full lifecycle of the
    // global retry-budget-looking counter at 0x390F98 (read/negated inside
    // FUN_0011bfb0 at 0x11c0b8/0x11c2fc, feeding func_11B010's stack-passed
    // "clean success" return value) -- does it ever get reset, what writes
    // it, and is its currently-exhausted (-11) state something our own
    // fixes indirectly caused or a pre-existing condition.
    if (guestAddr >= 0x390f98u && guestAddr < 0x390f9cu)
    {
        static std::atomic<uint32_t> s_watch390f98LogCount{0u};
        if (s_watch390f98LogCount.fetch_add(1u, std::memory_order_relaxed) < 200u)
        {
            std::cerr << "[watch-390f98] size=" << std::dec << size
                      << " valueLo=0x" << std::hex << valueLo
                      << " pc=0x" << (ctx ? ctx->pc : 0u)
                      << std::dec << std::endl;
        }
    }
    // TODO we dont need this anymore so on next release it will be deleted
}

inline void ps2TraceGuestRangeWrite(uint8_t *rdram,
                                    uint32_t guestAddr,
                                    uint32_t size,
                                    const char *op,
                                    const R5900Context *ctx)
{
    (void)rdram;
    (void)guestAddr;
    (void)size;
    (void)op;
    (void)ctx;
    // TODO we dont need this anymore so on next release it will be deleted
}

class PS2Runtime
{
public:
    struct IoPaths
    {
        std::filesystem::path elfPath;
        std::filesystem::path elfDirectory;
        std::filesystem::path hostRoot;
        std::filesystem::path cdRoot;
        std::filesystem::path mcRoot;
        std::filesystem::path cdImage;
    };

    PS2Runtime();
    ~PS2Runtime();

    bool initialize(const char *title = "PS2 Game");
    bool syncCoreSubsystems();
    bool loadELF(const std::string &elfPath);
    void run();

    void setIopPluginSearchPaths(std::vector<std::filesystem::path> paths);
    [[nodiscard]] ps2x::iop::DebugSnapshot iopDebugSnapshot() const;

    using DebugUiCallback = void (*)(PS2Runtime &runtime, void *userData);
    void setDebugUiCallbacks(DebugUiCallback initCallback,
                             DebugUiCallback drawCallback,
                             DebugUiCallback shutdownCallback,
                             void *userData);

    using RecompiledFunction = void (*)(uint8_t *, R5900Context *, PS2Runtime *);

    enum class GuestBranchKind
    {
        DirectJump,
        DirectCall,
        IndirectJump,
        IndirectCall,
        Return,
    };

    enum class MissingFunctionPolicy : uint32_t
    {
        // Strict mode for tests/CI: log the bad target and request the runtime to stop.
        Stop = 0,

        // Debug mode: log once, leave ctx->pc on the bad target, and let the caller unwind.
        ContinueToTarget = 1,

        // Debug mode: same as ContinueToTarget, but triggers a debugger break once on MSVC.
        BreakOnce = 2,

        // Escape hatch only: skip missing calls by returning to fallthrough (it can hide guest bugs)
        SkipCallDebug = 3,
    };

    bool replaceFunction(uint32_t address, RecompiledFunction func);
    // TODO remove this later need to update all tests
    bool registerFunction(uint32_t address, RecompiledFunction func);
    RecompiledFunction lookupFunction(uint32_t address);
    bool hasFunction(uint32_t address) const;
    bool dispatchGuestBranch(uint8_t *rdram,
                             R5900Context *ctx,
                             uint32_t targetPc,
                             uint32_t sourcePc,
                             uint32_t fallthroughPc,
                             GuestBranchKind kind,
                             const char *debugName);
    void reportMissingFunction(uint8_t *rdram,
                               R5900Context *ctx,
                               uint32_t targetPc,
                               uint32_t sourcePc,
                               GuestBranchKind kind,
                               const char *debugName);
    void setMissingFunctionPolicy(MissingFunctionPolicy policy);
    MissingFunctionPolicy missingFunctionPolicy() const;
    void resetMissingFunctionReportOnce();

    static const IoPaths &getIoPaths();
    static void setIoPaths(const IoPaths &paths);
    static void configureIoPathsFromElf(const std::string &elfPath);

    void SignalException(R5900Context *ctx, PS2Exception exception);

    void executeVU0Microprogram(uint8_t *rdram, R5900Context *ctx, uint32_t address);
    void vu0StartMicroProgram(uint8_t *rdram, R5900Context *ctx, uint32_t address);

public:
    void handleSyscall(uint8_t *rdram, R5900Context *ctx);
    void handleSyscall(uint8_t *rdram, R5900Context *ctx, uint32_t encodedSyscallId);
    void handleBreak(uint8_t *rdram, R5900Context *ctx);

    void handleTrap(uint8_t *rdram, R5900Context *ctx);
    void handleTLBR(uint8_t *rdram, R5900Context *ctx);
    void handleTLBWI(uint8_t *rdram, R5900Context *ctx);
    void handleTLBWR(uint8_t *rdram, R5900Context *ctx);
    void handleTLBP(uint8_t *rdram, R5900Context *ctx);
    void clearLLBit(R5900Context *ctx);
    void configureGuestHeap(uint32_t guestBase, uint32_t guestLimit = PS2_RAM_SIZE);
    uint32_t guestMalloc(uint32_t size, uint32_t alignment = 16u);
    uint32_t guestCalloc(uint32_t count, uint32_t size, uint32_t alignment = 16u);
    uint32_t guestRealloc(uint32_t guestAddr, uint32_t newSize, uint32_t alignment = 16u);
    void guestFree(uint32_t guestAddr);
    uint32_t guestHeapBase() const;
    uint32_t guestHeapEnd() const;
    uint32_t guestHeapLimit() const;
    uint32_t reserveAsyncCallbackStack(uint32_t size, uint32_t alignment = 16u);

    void drainCompletedDmacHandlers(uint8_t *rdram);

    void requestStop();
    bool isStopRequested() const;

    EeScheduler &eeScheduler();
    const EeScheduler &eeScheduler() const;
    // Lazily opens the real DQ8 disc image on first call (see project memory
    // 2026-08-27: validated standalone against the real ISO before this
    // integration). Returns nullptr if the disc image isn't found/valid.
    // Path is hardcoded for now -- no config system exists yet for this.
    Ps2DiscFs *discFs();
    void postEeEvent(EeEvent event);
    bool eeCheckpointDue(uint32_t cycles = 32u) noexcept;
    [[noreturn]] void eeWaitVSyncTicks(uint32_t ticks, uint32_t resumePc);

    struct EeExitHandlerRegistration
    {
        uint32_t function = 0;
        uint32_t argument = 0;
    };
    void addEeExitHandler(int threadId, uint32_t function, uint32_t argument);
    std::vector<EeExitHandlerRegistration> takeEeExitHandlers(int threadId);
    void removeEeExitHandlers(int threadId);
    bool findEeSyscallOverride(uint32_t syscallNumber, uint32_t &handler) const;
    void setEeSyscallOverride(uint8_t *rdram, uint32_t syscallNumber, uint32_t handler);
    void initializeEeKernelState(uint8_t *rdram);

    uint8_t Load8(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr);
    uint16_t Load16(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr);
    uint32_t Load32(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr);
    uint64_t Load64(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr);
    __m128i Load128(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr);

    void Store8(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, uint8_t value);
    void Store16(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, uint16_t value);
    void Store32(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, uint32_t value);
    void Store64(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, uint64_t value);
    void Store128(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, __m128i value);
    void kickGifDmaChainFromMMIO(uint8_t *rdram,
                                 R5900Context *ctx,
                                 uint32_t dPcrValue,
                                 uint32_t dStatValue,
                                 uint32_t tadr,
                                 uint32_t chcr);

    static inline bool isSpecialAddress(uint32_t addr)
    {
        return Ps2IsSpecialAddress(addr);
    }

public:
    inline R5900Context &cpu() { return m_cpuContext; }
    inline const R5900Context &cpu() const { return m_cpuContext; }

    inline PS2Memory &memory() { return m_memory; }
    inline const PS2Memory &memory() const { return m_memory; }

    inline GS &gs() { return m_gs; }
    inline const GS &gs() const { return m_gs; }
    inline GifArbiter &gifArbiter() { return m_gifArbiter; }
    inline const GifArbiter &gifArbiter() const { return m_gifArbiter; }
    inline VU1Interpreter &vu0() { return m_vu0; }
    inline const VU1Interpreter &vu0() const { return m_vu0; }
    inline VU1Interpreter &vu1() { return m_vu1; }
    inline const VU1Interpreter &vu1() const { return m_vu1; }

    inline PS2AudioBackend &audioBackend() { return m_audioBackend; }
    inline const PS2AudioBackend &audioBackend() const { return m_audioBackend; }
    inline PSPadBackend &padBackend() { return m_padBackend; }
    inline const PSPadBackend &padBackend() const { return m_padBackend; }

private:
    struct GuestHeapBlock
    {
        uint32_t addr = 0;
        uint32_t size = 0;
        bool free = true;
    };

    static uint32_t alignGuestHeapValue(uint32_t value, uint32_t alignment);
    static bool isGuestHeapAlignmentValid(uint32_t alignment);
    static uint32_t normalizeGuestHeapAlignment(uint32_t alignment);
    uint32_t clampGuestHeapBase(uint32_t guestBase) const;
    uint32_t clampGuestHeapLimit(uint32_t guestLimit) const;
    void resetGuestHeapLocked(uint32_t guestBase, uint32_t guestLimit);
    void ensureGuestHeapInitializedLocked();
    int32_t findGuestHeapBlockIndexLocked(uint32_t guestAddr) const;
    uint32_t allocateGuestBlockLocked(uint32_t size, uint32_t alignment);
    void freeGuestBlockLocked(uint32_t guestAddr);
    void coalesceGuestHeapLocked();
    void HandleIntegerOverflow(R5900Context *ctx);

    [[nodiscard]] ps2x::iop::RpcAbi selectIopRpcAbi(const ps2x::iop::RpcAbiRequest &request) const;
    [[nodiscard]] ps2x::iop::RpcResult handleIopRpc(uint8_t *rdram, R5900Context *ctx, ps2x::iop::RpcRequest request);
    void notifyIopSifTransfer(uint8_t *rdram, const ps2x::iop::SifTransfer &transfer);
    void resetIop();

    friend class PS2IopTransport;
    friend class EeScheduler;

private:
    PS2Memory m_memory;
    GifArbiter m_gifArbiter;
    GS m_gs;
    std::unique_ptr<PS2IopHostAdapter> m_iopHost;
    std::unique_ptr<ps2x::iop::IopSubsystem> m_iopSubsystem;
    PS2AudioBackend m_audioBackend;
    PSPadBackend m_padBackend;
    VU1Interpreter m_vu0{VU1Interpreter::Unit::VU0};
    VU1Interpreter m_vu1{VU1Interpreter::Unit::VU1};
    R5900Context m_cpuContext;
    std::unique_ptr<EeScheduler> m_eeScheduler;
    int m_nestedCallDepth = 0;
    std::unique_ptr<Ps2DiscFs> m_discFs;
    bool m_discFsOpenAttempted = false;
    mutable std::mutex m_eeKernelStateMutex;
    std::unordered_map<int, std::vector<EeExitHandlerRegistration>> m_eeExitHandlers;
    std::unordered_map<uint32_t, uint32_t> m_eeSyscallOverrides;
    std::unordered_set<uint32_t> m_eeSyscallMirrorAddresses;
    mutable std::mutex m_guestHeapMutex;
    mutable std::mutex m_asyncCallbackStackMutex;
    std::vector<GuestHeapBlock> m_guestHeapBlocks;
    uint32_t m_guestHeapBase = 0x00100000u;
    uint32_t m_guestHeapEnd = 0x00100000u;
    uint32_t m_guestHeapLimit = PS2_RAM_SIZE;
    uint32_t m_guestHeapSuggestedBase = 0x00100000u;
    bool m_guestHeapConfigured = false;
    uint32_t m_asyncCallbackStackFloor = 0x01F00000u;
    uint32_t m_asyncCallbackStackTop = PS2_RAM_SIZE;

    std::atomic<uint32_t> m_missingFunctionPolicy{static_cast<uint32_t>(MissingFunctionPolicy::ContinueToTarget)};
    std::atomic<bool> m_missingFunctionReported{false};
    std::atomic<bool> m_stopRequested{false};
    DebugUiCallback m_debugUiInitCallback = nullptr;
    DebugUiCallback m_debugUiDrawCallback = nullptr;
    DebugUiCallback m_debugUiShutdownCallback = nullptr;
    void *m_debugUiUserData = nullptr;
    bool m_debugUiInitialized = false;

public:
    std::atomic<uint32_t> m_debugPc{0};
    std::atomic<uint32_t> m_debugRa{0};
    std::atomic<uint32_t> m_debugSp{0};
    std::atomic<uint32_t> m_debugGp{0};

private:
    struct LoadedModule
    {
        std::string name;
        uint32_t baseAddress;
        size_t size;
        bool active;
    };

    std::vector<LoadedModule> m_loadedModules;
    uint8_t *m_boundRdram = nullptr;
    uint8_t *m_boundGSVram = nullptr;
};

// Generated by ps2xRecomp in ps2xRuntime/src/runner/register_functions.cpp.
extern const uint32_t g_ps2RecompiledFunctionTableBase;
extern const uint32_t g_ps2RecompiledFunctionTableEnd;
extern const uint32_t g_ps2RecompiledFunctionTableSlotCount;
extern PS2Runtime::RecompiledFunction g_ps2RecompiledFunctionTable[];

#endif // PS2_RUNTIME_H
