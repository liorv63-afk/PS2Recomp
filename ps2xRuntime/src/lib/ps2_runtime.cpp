#include "ps2_runtime.h"
#include "ps2_log.h"
#include "ps2_stubs.h"
#include "ps2_syscalls.h"
#include "game_overrides.h"
#include "ps2_runtime_macros.h"
#include "runtime/gs/gs_frontend.h"
#include "runtime/ee_scheduler.h"
#include "ThreadNaming.h"
#include "Kernel/Stubs/Audio.h"
#include "Kernel/Stubs/GS.h"
#include "Kernel/Stubs/MPEG.h"
#include "ps2_host_backend.h"
#include "ps2_iop_host.h"
#include "ps2x/iop/iop_subsystem.h"

#include <iostream>
#include <fstream>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <chrono>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <sstream>

// Force-links per-game override translation units that would otherwise be
// dropped by the linker from this static library (see DQ8.cpp for why).
extern "C" void ps2x_force_link_dq8_overrides();

namespace ps2_stubs
{
    void resetSifState();
}

#define ELF_MAGIC 0x464C457F // "\x7FELF" in little endian
#define ET_EXEC 2            // Executable file
#define EM_MIPS 8            // MIPS architecture
#define PT_LOAD 1            // Loadable segment

static constexpr int FB_WIDTH = 640;
static constexpr int FB_HEIGHT = 512;
static constexpr int DEFAULT_DISPLAY_HEIGHT = 448;
static constexpr uint32_t DEFAULT_FB_SIZE = FB_WIDTH * FB_HEIGHT * 4;
static constexpr uint32_t DEFAULT_FB_ADDR = (PS2_RAM_SIZE - DEFAULT_FB_SIZE - 0x10000u);
#if defined(PLATFORM_VITA)
static constexpr int HOST_WINDOW_WIDTH = 960;
static constexpr int HOST_WINDOW_HEIGHT = 544;
#else
static constexpr int HOST_WINDOW_WIDTH = FB_WIDTH;
static constexpr int HOST_WINDOW_HEIGHT = DEFAULT_DISPLAY_HEIGHT;
#endif
struct ElfHeader
{
    uint32_t magic;
    uint8_t elf_class;
    uint8_t endianness;
    uint8_t version;
    uint8_t os_abi;
    uint8_t abi_version;
    uint8_t padding[7];
    uint16_t type;
    uint16_t machine;
    uint32_t version2;
    uint32_t entry;
    uint32_t phoff;
    uint32_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
};

struct ProgramHeader
{
    uint32_t type;
    uint32_t offset;
    uint32_t vaddr;
    uint32_t paddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
};

namespace
{
    constexpr uint32_t kGuestHeapDefaultBase = 0x00100000u;
    constexpr uint32_t kGuestHeapDefaultAlignment = 16u;
    constexpr uint32_t kGuestHeapSafetyPad = 0x1000u;
    constexpr uint32_t kGuestHeapHardLimit = 0x01F00000u;

    constexpr uint32_t COP0_CAUSE_EXCCODE_MASK = 0x0000007Cu;
    constexpr uint32_t COP0_CAUSE_BD = 0x80000000u;
    constexpr uint32_t COP0_STATUS_EXL = 0x00000002u;
    constexpr uint32_t COP0_STATUS_BEV = 0x00400000u;
    constexpr uint32_t EXCEPTION_VECTOR_GENERAL = 0x80000080u;
    constexpr uint32_t EXCEPTION_VECTOR_TLB_REFILL = 0x80000000u;
    constexpr uint32_t EXCEPTION_VECTOR_BOOT = 0xBFC00200u;

    struct DispatchHistory
    {
        std::array<uint32_t, 64> pcs{};
        uint32_t next = 0u;
        bool wrapped = false;
    };

    thread_local DispatchHistory g_dispatchHistory;

    bool computeFileCrc32(const std::string &path, uint32_t &crcOut)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
        {
            return false;
        }

        static const std::array<uint32_t, 256> table = []
        {
            std::array<uint32_t, 256> values{};
            for (uint32_t i = 0; i < values.size(); ++i)
            {
                uint32_t value = i;
                for (uint32_t bit = 0; bit < 8; ++bit)
                {
                    value = (value & 1u) ? (0xEDB88320u ^ (value >> 1u)) : (value >> 1u);
                }
                values[i] = value;
            }
            return values;
        }();

        uint32_t crc = 0xFFFFFFFFu;
        std::array<uint8_t, 16 * 1024> buffer{};
        while (file.good())
        {
            file.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize count = file.gcount();
            for (std::streamsize i = 0; i < count; ++i)
            {
                crc = table[(crc ^ buffer[static_cast<size_t>(i)]) & 0xFFu] ^ (crc >> 8u);
            }
        }
        if (file.bad())
        {
            return false;
        }
        crcOut = ~crc;
        return true;
    }

    void pushDispatchPc(uint32_t pc)
    {
        DispatchHistory &h = g_dispatchHistory;
        h.pcs[h.next] = pc;
        h.next = (h.next + 1u) % static_cast<uint32_t>(h.pcs.size());
        if (h.next == 0u)
        {
            h.wrapped = true;
        }
    }

    std::string formatDispatchHistory()
    {
        const DispatchHistory &h = g_dispatchHistory;
        const uint32_t count = h.wrapped ? static_cast<uint32_t>(h.pcs.size()) : h.next;
        if (count == 0u)
        {
            return "(empty)";
        }

        std::ostringstream oss;
        bool first = true;
        for (uint32_t i = 0u; i < count; ++i)
        {
            const uint32_t idx = (h.next + h.pcs.size() - count + i) % static_cast<uint32_t>(h.pcs.size());
            if (!first)
            {
                oss << " -> ";
            }
            first = false;
            oss << "0x" << std::hex << h.pcs[idx];
        }
        return oss.str();
    }

    uint32_t selectExceptionVector(const R5900Context *ctx, bool tlbRefill)
    {
        if (ctx->cop0_status & COP0_STATUS_BEV)
        {
            return EXCEPTION_VECTOR_BOOT;
        }
        return tlbRefill ? EXCEPTION_VECTOR_TLB_REFILL : EXCEPTION_VECTOR_GENERAL;
    }

    void seedVu0IdleSuccess(R5900Context *ctx)
    {
        if (!ctx)
        {
            return;
        }

        ctx->vu0_clip_flags = 0;
        ctx->vu0_clip_flags2 = 0;
        ctx->vu0_mac_flags = 0;
        ctx->vu0_status = 0;
        ctx->vu0_q = 1.0f;
        ctx->vu0_r = _mm_castsi128_ps(_mm_set1_epi32(0x3F800000));
        ctx->vu0_vpu_stat = 0;
        ctx->vu0_vpu_stat2 = 0;
    }

    void copyVu0ContextToState(const R5900Context *ctx, VU1State &state)
    {
        std::memset(&state, 0, sizeof(state));

        for (uint32_t i = 0; i < 32u; ++i)
        {
            _mm_storeu_ps(state.vf[i], ctx->vu0_vf[i]);
        }
        for (uint32_t i = 0; i < 16u; ++i)
        {
            state.vi[i] = static_cast<int16_t>(ctx->vi[i]);
        }

        _mm_storeu_ps(state.acc, ctx->vu0_acc);
        state.q = ctx->vu0_q;
        state.p = ctx->vu0_p;
        state.i = ctx->vu0_i;
        alignas(16) uint32_t rWords[4]{};
        _mm_storeu_si128(reinterpret_cast<__m128i *>(rWords), _mm_castps_si128(ctx->vu0_r));
        state.r = 0x3F800000u | (rWords[0] & 0x007FFFFFu);
        state.pc = ctx->vu0_pc;
        state.mac = ctx->vu0_mac_flags;
        state.clip = ctx->vu0_clip_flags;
        state.status = ctx->vu0_status;
        state.itop = ctx->vu0_itop;
        state.dBitEnabled = (ctx->vu0_fbrst & (1u << 2)) != 0u;
        state.tBitEnabled = (ctx->vu0_fbrst & (1u << 3)) != 0u;

        state.vf[0][0] = 0.0f;
        state.vf[0][1] = 0.0f;
        state.vf[0][2] = 0.0f;
        state.vf[0][3] = 1.0f;
        state.vi[0] = 0;
    }

    void copyVu0StateToContext(const VU1State &state, R5900Context *ctx)
    {
        for (uint32_t i = 0; i < 32u; ++i)
        {
            ctx->vu0_vf[i] = _mm_loadu_ps(state.vf[i]);
        }
        for (uint32_t i = 0; i < 16u; ++i)
        {
            ctx->vi[i] = static_cast<uint16_t>(state.vi[i]);
        }

        ctx->vu0_acc = _mm_loadu_ps(state.acc);
        ctx->vu0_q = state.q;
        ctx->vu0_p = state.p;
        ctx->vu0_i = state.i;
        ctx->vu0_r = _mm_castsi128_ps(_mm_set1_epi32(static_cast<int32_t>(state.r)));
        ctx->vu0_mac_flags = state.mac;
        ctx->vu0_clip_flags = state.clip;
        ctx->vu0_clip_flags2 = state.clip;
        ctx->vu0_status = static_cast<uint16_t>(state.status);
        ctx->vu0_itop = state.itop;
        ctx->vu0_pc = state.pc;
        ctx->vu0_tpc = state.pc;
        ctx->vu0_vpu_stat = (ctx->vu0_vpu_stat & 0xFF00u) | (state.stoppedByD ? (1u << 1) : 0u) | (state.stoppedByT ? (1u << 2) : 0u);
        ctx->vu0_vpu_stat2 = 0;

        ctx->vu0_vf[0] = _mm_set_ps(1.0f, 0.0f, 0.0f, 0.0f);
        ctx->vi[0] = 0;
    }

    void raiseCop0Exception(R5900Context *ctx, uint32_t exceptionCode, bool tlbRefill = false)
    {
        if (ctx->in_delay_slot)
        {
            ctx->cop0_epc = ctx->branch_pc;
            ctx->cop0_cause = (ctx->cop0_cause & ~COP0_CAUSE_EXCCODE_MASK) |
                              ((exceptionCode << 2) & COP0_CAUSE_EXCCODE_MASK) |
                              COP0_CAUSE_BD;
        }
        else
        {
            ctx->cop0_epc = ctx->pc;
            ctx->cop0_cause = (ctx->cop0_cause & ~(COP0_CAUSE_EXCCODE_MASK | COP0_CAUSE_BD)) |
                              ((exceptionCode << 2) & COP0_CAUSE_EXCCODE_MASK);
        }

        ctx->cop0_status |= COP0_STATUS_EXL;
        ctx->pc = selectExceptionVector(ctx, tlbRefill);
        ctx->in_delay_slot = false;
    }

    std::filesystem::path normalizeAbsolutePath(const std::filesystem::path &path)
    {
        if (path.empty())
        {
            return {};
        }

#if defined(PLATFORM_VITA)
        const std::string generic = path.generic_string();
        const std::size_t colon = generic.find(':');
        if (colon != std::string::npos && colon != 0u)
        {
            const std::size_t slash = generic.find_first_of("/\\");
            if (slash == std::string::npos || colon < slash)
            {
                return path.lexically_normal();
            }
        }
#endif

        std::error_code ec;
        const std::filesystem::path absolute = std::filesystem::absolute(path, ec);
        if (ec)
        {
            return path.lexically_normal();
        }
        return absolute.lexically_normal();
    }

    PS2Runtime::IoPaths &runtimeIoPaths()
    {
        static PS2Runtime::IoPaths paths = []()
        {
            PS2Runtime::IoPaths defaults;
            std::error_code ec;
            const std::filesystem::path cwd = std::filesystem::current_path(ec);
            defaults.elfDirectory = ec ? std::filesystem::path(".") : cwd.lexically_normal();
            defaults.hostRoot = defaults.elfDirectory;
            defaults.cdRoot = defaults.elfDirectory;
            defaults.mcRoot = defaults.elfDirectory / "mc0";
            return defaults;
        }();

        return paths;
    }

    std::string readGuestPrintableString(const uint8_t *rdram, uint32_t addr, size_t maxLen)
    {
        std::string out;
        if (!rdram || maxLen == 0)
        {
            return out;
        }

        out.reserve(std::min<size_t>(maxLen, 64));
        for (size_t i = 0; i < maxLen; ++i)
        {
            const char ch = static_cast<char>(rdram[(addr + static_cast<uint32_t>(i)) & PS2_RAM_MASK]);
            if (ch == '\0')
            {
                break;
            }
            if (ch >= 0x20 && ch < 0x7F)
            {
                out.push_back(ch);
            }
            else
            {
                out.push_back('.');
            }
        }
        return out;
    }
}

static void UploadFrame(Texture2D &tex, PS2Runtime *rt, uint32_t &outWidth, uint32_t &outHeight)
{
    static uint64_t s_lastPresentationTick = std::numeric_limits<uint64_t>::max();
    static bool s_hasLatchedInitialFrame = false;
    static uint32_t s_lastDisplayFbp = std::numeric_limits<uint32_t>::max();
    static uint32_t s_lastSourceFbp = std::numeric_limits<uint32_t>::max();
    static bool s_lastPreferred = false;
    static uint32_t s_lastWidth = 0u;
    static uint32_t s_lastHeight = 0u;
    static bool s_hasUploadedFrame = false;
    static std::vector<uint8_t> s_scratch;
    static std::vector<uint8_t> s_uploadBuffer(DEFAULT_FB_SIZE, 0u);

    const uint64_t currentTick = rt->eeScheduler().currentVSyncTick();
    const bool needsLatch = !s_hasLatchedInitialFrame || currentTick != s_lastPresentationTick;
    if (needsLatch)
    {
        rt->gs().latchHostPresentationFrame();
        s_lastPresentationTick = currentTick;
        s_hasLatchedInitialFrame = true;
    }
    else if (s_hasUploadedFrame)
    {
        outWidth = (s_lastWidth != 0u) ? s_lastWidth : FB_WIDTH;
        outHeight = (s_lastHeight != 0u) ? s_lastHeight : DEFAULT_DISPLAY_HEIGHT;
        return;
    }

    s_scratch.clear();
    uint32_t width = 0u;
    uint32_t height = 0u;
    uint32_t displayFbp = 0u;
    uint32_t sourceFbp = 0u;
    bool usedPreferredDisplaySource = false;
    if (!rt->gs().copyLatchedHostPresentationFrame(s_scratch,
                                                   width,
                                                   height,
                                                   &displayFbp,
                                                   &sourceFbp,
                                                   &usedPreferredDisplaySource))
    {
        Image blank = GenImageColor(FB_WIDTH, FB_HEIGHT, MAGENTA);
        UpdateTexture(tex, blank.data);
        UnloadImage(blank);
        outWidth = FB_WIDTH;
        outHeight = DEFAULT_DISPLAY_HEIGHT;
        s_lastWidth = outWidth;
        s_lastHeight = outHeight;
        s_hasUploadedFrame = true;
        return;
    }

    PS2_IF_AGRESSIVE_LOGS({
        static uint32_t s_uploadDebugCount = 0u;
        if (s_uploadDebugCount < 128u ||
            displayFbp != s_lastDisplayFbp ||
            sourceFbp != s_lastSourceFbp ||
            usedPreferredDisplaySource != s_lastPreferred ||
            width != s_lastWidth ||
            height != s_lastHeight)
        {
            std::cout << "[frame:upload] idx=" << s_uploadDebugCount
                      << " tick=" << currentTick
                      << " displayFbp=" << displayFbp
                      << " sourceFbp=" << sourceFbp
                      << " size=" << width << "x" << height
                      << " preferred=" << static_cast<uint32_t>(usedPreferredDisplaySource ? 1u : 0u)
                      << std::endl;
        }
        ++s_uploadDebugCount;
    });
    s_lastDisplayFbp = displayFbp;
    s_lastSourceFbp = sourceFbp;
    s_lastPreferred = usedPreferredDisplaySource;
    s_lastWidth = width;
    s_lastHeight = height;

    std::fill(s_uploadBuffer.begin(), s_uploadBuffer.end(), 0u);
    if (!s_scratch.empty() && width != 0u && height != 0u)
    {
        const uint32_t copyWidth = std::min<uint32_t>(width, FB_WIDTH);
        const uint32_t copyHeight = std::min<uint32_t>(height, FB_HEIGHT);
        const size_t srcRowBytes = static_cast<size_t>(width) * 4u;
        const size_t dstRowBytes = static_cast<size_t>(FB_WIDTH) * 4u;
        const size_t copyRowBytes = static_cast<size_t>(copyWidth) * 4u;
        for (uint32_t y = 0; y < copyHeight; ++y)
        {
            const size_t srcOffset = static_cast<size_t>(y) * srcRowBytes;
            const size_t dstOffset = static_cast<size_t>(y) * dstRowBytes;
            if (srcOffset + copyRowBytes > s_scratch.size() ||
                dstOffset + copyRowBytes > s_uploadBuffer.size())
            {
                break;
            }
            std::memcpy(s_uploadBuffer.data() + dstOffset, s_scratch.data() + srcOffset, copyRowBytes);
        }
    }

    UpdateTexture(tex, s_uploadBuffer.data());
    outWidth = width;
    outHeight = height;
    s_hasUploadedFrame = true;
}

PS2Runtime::PS2Runtime()
{
    m_iopHost = std::make_unique<PS2IopHostAdapter>(*this);
    m_iopSubsystem = std::make_unique<ps2x::iop::IopSubsystem>(*m_iopHost);
    m_eeScheduler = std::make_unique<EeScheduler>(*this);
#if defined(PS2X_IOP_ENABLE_PLUGINS) && PS2X_IOP_ENABLE_PLUGINS && \
    !defined(PLATFORM_VITA) && (defined(_WIN32) || defined(__linux__))
    if (const char *applicationDirectory = GetApplicationDirectory();
        applicationDirectory && applicationDirectory[0] != '\0')
    {
        m_iopSubsystem->setPluginSearchPaths({std::filesystem::path(applicationDirectory) / "iop_plugins"});
    }
#endif

    // Assign rather than memset: R5900Context's constructor zeroes itself and
    // then applies the COP0 reset values, which a memset here would discard.
    m_cpuContext = R5900Context{};

    // R0 is always zero in MIPS
    m_cpuContext.r[0] = _mm_set1_epi32(0);
    m_cpuContext.vu0_vf[0] = _mm_set_ps(1.0f, 0.0f, 0.0f, 0.0f);
    m_cpuContext.vu0_q = 1.0f;
    m_cpuContext.vu0_r = _mm_castsi128_ps(_mm_set1_epi32(0x3F800000));

    // Stack pointer (SP) and global pointer (GP) will be set by the loaded ELF

    m_loadedModules.clear();
    m_guestHeapBlocks.clear();
    m_guestHeapBase = kGuestHeapDefaultBase;
    m_guestHeapEnd = kGuestHeapDefaultBase;
    m_guestHeapLimit = std::min(kGuestHeapHardLimit, PS2_RAM_SIZE);
    m_guestHeapSuggestedBase = kGuestHeapDefaultBase;
    m_guestHeapConfigured = false;
    m_asyncCallbackStackFloor = std::min(kGuestHeapHardLimit, PS2_RAM_SIZE);
    m_asyncCallbackStackTop = PS2_RAM_SIZE;
}

void PS2Runtime::setDebugUiCallbacks(DebugUiCallback initCallback,
                                     DebugUiCallback drawCallback,
                                     DebugUiCallback shutdownCallback,
                                     void *userData)
{
    if (m_debugUiInitialized && m_debugUiShutdownCallback)
    {
        m_debugUiShutdownCallback(*this, m_debugUiUserData);
        m_debugUiInitialized = false;
    }

    m_debugUiInitCallback = initCallback;
    m_debugUiDrawCallback = drawCallback;
    m_debugUiShutdownCallback = shutdownCallback;
    m_debugUiUserData = userData;
}

PS2Runtime::~PS2Runtime()
{
    try
    {
        requestStop();
        m_iopSubsystem.reset();
        m_iopHost.reset();
#if defined(PLATFORM_VITA)
        m_audioBackend.stopAll();
        m_audioBackend.setAudioReady(false);
#else
        if (IsAudioDeviceReady())
        {
            CloseAudioDevice();
            m_audioBackend.setAudioReady(false);
        }
#endif
        if (m_debugUiInitialized && m_debugUiShutdownCallback)
        {
            m_debugUiShutdownCallback(*this, m_debugUiUserData);
            m_debugUiInitialized = false;
        }

        if (IsWindowReady())
        {
            CloseWindow();
        }

        m_loadedModules.clear();
    }
    catch (const std::exception &e)
    {
        std::cerr << "[~PS2Runtime] cleanup exception: " << e.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "[~PS2Runtime] cleanup exception: unknown" << std::endl;
    }
}

void PS2Runtime::setIopPluginSearchPaths(std::vector<std::filesystem::path> paths)
{
    m_iopSubsystem->setPluginSearchPaths(std::move(paths));
}

ps2x::iop::RpcAbi PS2Runtime::selectIopRpcAbi(const ps2x::iop::RpcAbiRequest &request) const
{
    return m_iopSubsystem->selectRpcAbi(request);
}

ps2x::iop::RpcResult PS2Runtime::handleIopRpc(uint8_t *rdram, R5900Context *ctx, ps2x::iop::RpcRequest request)
{
    auto scope = m_iopHost->enterCall(ctx, rdram);
    request.callToken = scope.token();
    return m_iopSubsystem->handleRpc(request);
}

void PS2Runtime::notifyIopSifTransfer(uint8_t *rdram, const ps2x::iop::SifTransfer &transfer)
{
    auto scope = m_iopHost->enterCall(nullptr, rdram);
    m_iopSubsystem->onSifTransfer(transfer);
}

void PS2Runtime::resetIop()
{
    m_iopSubsystem->reset();
}

ps2x::iop::DebugSnapshot PS2Runtime::iopDebugSnapshot() const
{
    return m_iopSubsystem->debugSnapshot();
}

bool PS2Runtime::syncCoreSubsystems()
{
    uint8_t *const rdram = m_memory.getRDRAM();
    uint8_t *const gsVram = m_memory.getGSVRAM();
    if (!rdram || !gsVram)
    {
        return false;
    }

    if (m_boundRdram == rdram && m_boundGSVram == gsVram)
    {
        return true;
    }

    m_gs.init(gsVram, static_cast<uint32_t>(PS2_GS_VRAM_SIZE), &m_memory.gs());
    m_gifArbiter.setProcessPacketFn([this](const uint8_t *data, uint32_t size)
                                    { m_gs.processGIFPacket(data, size); });
    m_memory.setGifArbiter(&m_gifArbiter);
    m_memory.setVu1MscalCallback([this](uint32_t startPC, uint32_t top, uint32_t itop)
                                 {
                                     R5900Context *cpuContext = m_eeScheduler ? m_eeScheduler->currentContext() : nullptr;
                                     if (!cpuContext)
                                     {
                                         cpuContext = &m_cpuContext;
                                     }
                                     m_vu1.state().dBitEnabled =
                                         (cpuContext->vu0_fbrst & (1u << 10)) != 0u;
                                     m_vu1.state().tBitEnabled =
                                         (cpuContext->vu0_fbrst & (1u << 11)) != 0u;
                                     m_vu1.execute(m_memory.getVU1Code(), PS2_VU1_CODE_SIZE,
                                                   m_memory.getVU1Data(), PS2_VU1_DATA_SIZE,
                                                   m_gs, &m_memory, startPC, top, itop, 65536);
                                     cpuContext->vu0_vpu_stat =
                                         (cpuContext->vu0_vpu_stat & ~0x0600u) |
                                         (m_vu1.state().stoppedByD ? 0x0200u : 0u) |
                                         (m_vu1.state().stoppedByT ? 0x0400u : 0u); });
    m_memory.setVu1MscntCallback([this](uint32_t top, uint32_t itop)
                                 {
                                     R5900Context *cpuContext = m_eeScheduler ? m_eeScheduler->currentContext() : nullptr;
                                     if (!cpuContext)
                                     {
                                         cpuContext = &m_cpuContext;
                                     }
                                     m_vu1.state().dBitEnabled =
                                         (cpuContext->vu0_fbrst & (1u << 10)) != 0u;
                                     m_vu1.state().tBitEnabled =
                                         (cpuContext->vu0_fbrst & (1u << 11)) != 0u;
                                     m_vu1.resume(m_memory.getVU1Code(), PS2_VU1_CODE_SIZE,
                                                  m_memory.getVU1Data(), PS2_VU1_DATA_SIZE,
                                                  m_gs, &m_memory, top, itop, 65536);
                                     cpuContext->vu0_vpu_stat =
                                         (cpuContext->vu0_vpu_stat & ~0x0600u) |
                                         (m_vu1.state().stoppedByD ? 0x0200u : 0u) |
                                         (m_vu1.state().stoppedByT ? 0x0400u : 0u); });
    resetIop();
    m_vu0.reset();
    m_vu1.reset();

    m_boundRdram = rdram;
    m_boundGSVram = gsVram;
    return true;
}

bool PS2Runtime::initialize(const char *title)
{
    try
    {
        if (!m_memory.initialize())
        {
            std::cerr << "Failed to initialize PS2 memory" << std::endl;
            return false;
        }

        if (!syncCoreSubsystems())
        {
            std::cerr << "Failed to bind runtime core subsystems" << std::endl;
            return false;
        }
#if defined(PS2X_IOP_ENABLE_PLUGINS) && PS2X_IOP_ENABLE_PLUGINS && \
    !defined(PLATFORM_VITA) && (defined(_WIN32) || defined(__linux__))
        std::string pluginError;
        if (!m_iopSubsystem->loadPlugins(&pluginError))
        {
            std::cerr << "Failed to load IOP plugins: " << pluginError << std::endl;
            return false;
        }
#endif
#if defined(PLATFORM_VITA)
        InitWindow(HOST_WINDOW_WIDTH, HOST_WINDOW_HEIGHT, title); // raylib vita does not support audio
#else
        SetConfigFlags(FLAG_WINDOW_RESIZABLE);
        InitWindow(HOST_WINDOW_WIDTH, HOST_WINDOW_HEIGHT, title);
        InitAudioDevice();
        m_audioBackend.setAudioReady(IsAudioDeviceReady());
#endif
        SetTargetFPS(60);
        if (m_debugUiInitCallback)
        {
            m_debugUiInitCallback(*this, m_debugUiUserData);
            m_debugUiInitialized = true;
        }

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Failed to initialize PS2 runtime: " << e.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "Failed to initialize PS2 runtime: unknown exception" << std::endl;
    }

    return false;
}

bool PS2Runtime::loadELF(const std::string &elfPath)
{
    configureIoPathsFromElf(elfPath);

    std::ifstream file(elfPath, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open ELF file: " << elfPath << std::endl;
        return false;
    }

    file.seekg(0, std::ios::end);
    const std::streamoff fileSize = file.tellg();
    if (fileSize < static_cast<std::streamoff>(sizeof(ElfHeader)))
    {
        std::cerr << "ELF file is too small: " << elfPath << std::endl;
        return false;
    }
    file.seekg(0, std::ios::beg);

    ElfHeader header{};
    if (!file.read(reinterpret_cast<char *>(&header), sizeof(header)))
    {
        std::cerr << "Failed to read ELF header from: " << elfPath << std::endl;
        return false;
    }

    if (header.magic != ELF_MAGIC)
    {
        std::cerr << "Invalid ELF magic number" << std::endl;
        return false;
    }

    if (header.elf_class != 1u || header.endianness != 1u)
    {
        std::cerr << "Unsupported ELF format (expected 32-bit little-endian)." << std::endl;
        return false;
    }

    if (header.machine != EM_MIPS || header.type != ET_EXEC)
    {
        std::cerr << "Not a MIPS executable ELF file" << std::endl;
        return false;
    }

    if (header.phnum != 0u && header.phentsize < sizeof(ProgramHeader))
    {
        std::cerr << "Unsupported ELF program-header entry size: " << header.phentsize << std::endl;
        return false;
    }

    const uint64_t programHeaderTableEnd =
        static_cast<uint64_t>(header.phoff) +
        static_cast<uint64_t>(header.phnum) * static_cast<uint64_t>(header.phentsize);
    if (programHeaderTableEnd > static_cast<uint64_t>(fileSize))
    {
        std::cerr << "ELF program-header table is out of range." << std::endl;
        return false;
    }

    m_cpuContext.pc = header.entry;
    m_debugPc.store(m_cpuContext.pc, std::memory_order_relaxed);

    uint32_t maxLoadedRdramEnd = kGuestHeapDefaultBase;
    uint32_t moduleBase = std::numeric_limits<uint32_t>::max();
    uint32_t moduleEnd = 0u;
    bool loadedAnySegment = false;

    for (uint16_t i = 0; i < header.phnum; i++)
    {
        const uint64_t phOffset =
            static_cast<uint64_t>(header.phoff) +
            static_cast<uint64_t>(i) * static_cast<uint64_t>(header.phentsize);
        if (phOffset + sizeof(ProgramHeader) > static_cast<uint64_t>(fileSize))
        {
            std::cerr << "ELF program header " << i << " is out of range." << std::endl;
            return false;
        }

        ProgramHeader ph{};
        file.seekg(static_cast<std::streamoff>(phOffset), std::ios::beg);
        if (!file.read(reinterpret_cast<char *>(&ph), sizeof(ph)))
        {
            std::cerr << "Failed to read ELF program header " << i << std::endl;
            return false;
        }

        if (ph.type != PT_LOAD || ph.memsz == 0u)
        {
            continue;
        }

        if (ph.filesz > ph.memsz)
        {
            std::cerr << "ELF segment " << i << " has filesz > memsz." << std::endl;
            return false;
        }

        const uint64_t segmentFileEnd = static_cast<uint64_t>(ph.offset) + static_cast<uint64_t>(ph.filesz);
        if (segmentFileEnd > static_cast<uint64_t>(fileSize))
        {
            std::cerr << "ELF segment " << i << " exceeds file bounds." << std::endl;
            return false;
        }

        const bool scratch =
            ph.vaddr >= PS2_SCRATCHPAD_BASE &&
            ph.vaddr < (PS2_SCRATCHPAD_BASE + PS2_SCRATCHPAD_SIZE);

        uint32_t physAddr = 0u;
        try
        {
            physAddr = m_memory.translateAddress(ph.vaddr);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Failed to translate ELF segment " << i
                      << " virtual address 0x" << std::hex << ph.vaddr
                      << std::dec << ": " << e.what() << std::endl;
            return false;
        }
        const uint64_t regionSize = scratch ? static_cast<uint64_t>(PS2_SCRATCHPAD_SIZE)
                                            : static_cast<uint64_t>(PS2_RAM_SIZE);
        const uint64_t segmentMemEnd = static_cast<uint64_t>(physAddr) + static_cast<uint64_t>(ph.memsz);
        if (segmentMemEnd > regionSize)
        {
            std::cerr << "ELF segment " << i << " exceeds "
                      << (scratch ? "scratchpad" : "RDRAM")
                      << " bounds (vaddr=0x" << std::hex << ph.vaddr
                      << " memsz=0x" << ph.memsz << std::dec << ")." << std::endl;
            return false;
        }

        uint8_t *destBase = scratch ? m_memory.getScratchpad() : m_memory.getRDRAM();
        if (!destBase)
        {
            std::cerr << "ELF segment " << i << " has no destination memory backing." << std::endl;
            return false;
        }

        uint8_t *dest = destBase + physAddr;
        if (ph.filesz > 0u)
        {
            file.seekg(static_cast<std::streamoff>(ph.offset), std::ios::beg);
            if (!file.read(reinterpret_cast<char *>(dest), ph.filesz))
            {
                std::cerr << "Failed to read ELF segment " << i << " payload." << std::endl;
                return false;
            }
        }

        if (ph.memsz > ph.filesz)
        {
            std::memset(dest + ph.filesz, 0, ph.memsz - ph.filesz);
        }

        RUNTIME_LOG("Loading segment: 0x" << std::hex << ph.vaddr
                                          << " - 0x" << (static_cast<uint64_t>(ph.vaddr) + static_cast<uint64_t>(ph.memsz))
                                          << " (filesz: 0x" << ph.filesz
                                          << ", memsz: 0x" << ph.memsz << ")"
                                          << std::dec << std::endl);

        if (!scratch)
        {
            maxLoadedRdramEnd = std::max(maxLoadedRdramEnd, static_cast<uint32_t>(segmentMemEnd));
        }

        if (ph.flags & 0x1u) // PF_X
        {
            const uint64_t execEnd = static_cast<uint64_t>(ph.vaddr) + static_cast<uint64_t>(ph.filesz);
            if (execEnd <= std::numeric_limits<uint32_t>::max())
            {
                m_memory.registerCodeRegion(ph.vaddr, static_cast<uint32_t>(execEnd));
            }
        }

        loadedAnySegment = true;
        moduleBase = std::min(moduleBase, ph.vaddr);
        const uint64_t segmentVirtualEnd = static_cast<uint64_t>(ph.vaddr) + static_cast<uint64_t>(ph.memsz);
        const uint32_t clampedVirtualEnd =
            (segmentVirtualEnd > std::numeric_limits<uint32_t>::max())
                ? std::numeric_limits<uint32_t>::max()
                : static_cast<uint32_t>(segmentVirtualEnd);
        moduleEnd = std::max(moduleEnd, clampedVirtualEnd);
    }

    if (!loadedAnySegment)
    {
        std::cerr << "ELF contains no loadable PT_LOAD segments." << std::endl;
        return false;
    }

    if (maxLoadedRdramEnd > PS2_RAM_SIZE)
    {
        maxLoadedRdramEnd = PS2_RAM_SIZE;
    }

    const uint32_t paddedEnd = (maxLoadedRdramEnd > (PS2_RAM_SIZE - kGuestHeapSafetyPad))
                                   ? PS2_RAM_SIZE
                                   : (maxLoadedRdramEnd + kGuestHeapSafetyPad);
    const uint32_t suggestedHeapBase = alignGuestHeapValue(paddedEnd, kGuestHeapDefaultAlignment);
    {
        std::lock_guard<std::mutex> lock(m_guestHeapMutex);
        if (!m_guestHeapConfigured)
        {
            const uint32_t hardLimit = std::min(kGuestHeapHardLimit, PS2_RAM_SIZE);
            m_guestHeapSuggestedBase = std::min(suggestedHeapBase, hardLimit);
            m_guestHeapBase = m_guestHeapSuggestedBase;
            m_guestHeapEnd = m_guestHeapSuggestedBase;
            m_guestHeapLimit = hardLimit;
        }
    }
    {
        std::lock_guard<std::mutex> lock(m_asyncCallbackStackMutex);
        const uint32_t hardLimit = std::min(kGuestHeapHardLimit, PS2_RAM_SIZE);
        m_asyncCallbackStackFloor = std::min(std::max(hardLimit, suggestedHeapBase), PS2_RAM_SIZE);
        m_asyncCallbackStackTop = PS2_RAM_SIZE;
    }

    LoadedModule module;
    module.name = elfPath.substr(elfPath.find_last_of("/\\") + 1);
    module.baseAddress = (moduleBase == std::numeric_limits<uint32_t>::max()) ? 0x00100000u : moduleBase;
    module.size = (moduleEnd > module.baseAddress) ? static_cast<size_t>(moduleEnd - module.baseAddress) : 0u;
    module.active = true;

    m_loadedModules.push_back(module);

    uint32_t elfCrc32 = 0u;
    const bool elfCrc32Valid = computeFileCrc32(elfPath, elfCrc32);
    if (!elfCrc32Valid)
    {
        std::cerr << "[ps2xIOP] failed to compute ELF CRC32 for '" << elfPath << "'" << std::endl;
    }
    ps2x::iop::GameIdentity identity;
    identity.elfName = module.name;
    identity.entryPoint = m_cpuContext.pc;
    identity.crc32 = elfCrc32;
    std::string iopError;
    if (!m_iopSubsystem->configure(identity, &iopError))
    {
        std::cerr << "[ps2xIOP] failed to configure profile: " << iopError << std::endl;
        return false;
    }

    ps2x_force_link_dq8_overrides();

    ps2_game_overrides::applyMatching(*this,
                                      elfPath,
                                      m_cpuContext.pc,
                                      elfCrc32,
                                      elfCrc32Valid);

    // One-time proof that the real disc filesystem reader (see project
    // memory 2026-08-27) integrates and opens correctly inside the actual
    // runtime process, not just the standalone test it was validated with.
    (void)discFs();

    RUNTIME_LOG("ELF file loaded successfully. Entry point: 0x" << std::hex << m_cpuContext.pc << std::dec);
    return true;
}

const PS2Runtime::IoPaths &PS2Runtime::getIoPaths()
{
    return runtimeIoPaths();
}

void PS2Runtime::setIoPaths(const IoPaths &paths)
{
    IoPaths normalized = paths;
    normalized.elfPath = normalizeAbsolutePath(normalized.elfPath);
    normalized.elfDirectory = normalizeAbsolutePath(normalized.elfDirectory);
    normalized.hostRoot = normalizeAbsolutePath(normalized.hostRoot);
    normalized.cdRoot = normalizeAbsolutePath(normalized.cdRoot);
    normalized.mcRoot = normalizeAbsolutePath(normalized.mcRoot);
    normalized.cdImage = normalizeAbsolutePath(normalized.cdImage);

    if (normalized.elfDirectory.empty() && !normalized.elfPath.empty())
    {
        normalized.elfDirectory = normalized.elfPath.parent_path();
    }

    if (normalized.hostRoot.empty())
    {
        normalized.hostRoot = normalized.elfDirectory;
    }
    if (normalized.cdRoot.empty())
    {
        normalized.cdRoot = normalized.elfDirectory;
    }
    if (normalized.mcRoot.empty())
    {
        normalized.mcRoot = normalized.elfDirectory / "mc0";
    }

    runtimeIoPaths() = normalized;
}

void PS2Runtime::configureIoPathsFromElf(const std::string &elfPath)
{
    IoPaths paths = runtimeIoPaths();
    paths.elfPath = normalizeAbsolutePath(std::filesystem::path(elfPath));
    if (!paths.elfPath.empty())
    {
        paths.elfDirectory = paths.elfPath.parent_path();
    }

    if (!paths.elfDirectory.empty())
    {
        paths.hostRoot = paths.elfDirectory;
        paths.cdRoot = paths.elfDirectory;
        paths.mcRoot = paths.elfDirectory / "mc0";
    }

    setIoPaths(paths);
}

namespace
{
    bool generatedFunctionTableSlot(uint32_t address, uint32_t &slot)
    {
        if ((address & 3u) != 0u || g_ps2RecompiledFunctionTableSlotCount == 0u)
        {
            return false;
        }

        if (address < g_ps2RecompiledFunctionTableBase || address >= g_ps2RecompiledFunctionTableEnd)
        {
            return false;
        }

        const uint32_t offset = address - g_ps2RecompiledFunctionTableBase;
        slot = offset >> 2;
        return slot < g_ps2RecompiledFunctionTableSlotCount;
    }
}

bool PS2Runtime::replaceFunction(uint32_t address, RecompiledFunction func)
{
    uint32_t slot = 0u;
    if (!generatedFunctionTableSlot(address, slot))
    {
        std::cerr << "[function-table] cannot replace guest PC 0x" << std::hex << address
                  << ": outside generated dense table [0x" << g_ps2RecompiledFunctionTableBase
                  << ", 0x" << g_ps2RecompiledFunctionTableEnd << ")"
                  << std::dec << std::endl;
        return false;
    }

    g_ps2RecompiledFunctionTable[slot] = func;
    return true;
}

bool PS2Runtime::registerFunction(uint32_t address, RecompiledFunction func)
{
    return replaceFunction(address, func);
}

bool PS2Runtime::hasFunction(uint32_t address) const
{
    uint32_t slot = 0u;
    return generatedFunctionTableSlot(address, slot) && g_ps2RecompiledFunctionTable[slot] != nullptr;
}

const char *describeGuestBranchKind(PS2Runtime::GuestBranchKind kind)
{
    switch (kind)
    {
    case PS2Runtime::GuestBranchKind::DirectJump:
        return "DirectJump";
    case PS2Runtime::GuestBranchKind::DirectCall:
        return "DirectCall";
    case PS2Runtime::GuestBranchKind::IndirectJump:
        return "IndirectJump";
    case PS2Runtime::GuestBranchKind::IndirectCall:
        return "IndirectCall";
    case PS2Runtime::GuestBranchKind::Return:
        return "Return";
    default:
        return "Unknown";
    }
}

PS2Runtime::RecompiledFunction PS2Runtime::lookupFunction(uint32_t address)
{
    pushDispatchPc(address);

    uint32_t slot = 0u;
    if (generatedFunctionTableSlot(address, slot))
    {
        RecompiledFunction fn = g_ps2RecompiledFunctionTable[slot];
        if (fn != nullptr)
        {
            return fn;
        }
    }

    std::cerr << "Error: No exact recompiled function for guest PC 0x" << std::hex << address
              << " tableBase=0x" << g_ps2RecompiledFunctionTableBase
              << " tableEnd=0x" << g_ps2RecompiledFunctionTableEnd
              << " codeRegion=" << (m_memory.isCodeAddress(address) ? "yes" : "no")
              << " trace=" << formatDispatchHistory()
              << std::dec << std::endl;

    static RecompiledFunction missingFunction = [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t badPc = ctx->pc;
        runtime->reportMissingFunction(rdram,
                                       ctx,
                                       badPc,
                                       0u,
                                       PS2Runtime::GuestBranchKind::IndirectJump,
                                       "dispatch");
    };

    return missingFunction;
}

void PS2Runtime::setMissingFunctionPolicy(MissingFunctionPolicy policy)
{
    m_missingFunctionPolicy.store(static_cast<uint32_t>(policy), std::memory_order_release);
}

PS2Runtime::MissingFunctionPolicy PS2Runtime::missingFunctionPolicy() const
{
    return static_cast<MissingFunctionPolicy>(m_missingFunctionPolicy.load(std::memory_order_acquire));
}

void PS2Runtime::resetMissingFunctionReportOnce()
{
    m_missingFunctionReported.store(false, std::memory_order_release);
}

void PS2Runtime::reportMissingFunction(uint8_t *rdram,
                                       R5900Context *ctx,
                                       uint32_t targetPc,
                                       uint32_t sourcePc,
                                       GuestBranchKind kind,
                                       const char *debugName)
{
    const MissingFunctionPolicy policy = missingFunctionPolicy();
    const bool firstReport = !m_missingFunctionReported.exchange(true, std::memory_order_acq_rel);

    const uint32_t pc = ctx->pc;
    const uint32_t ra = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[31], 0));
    const uint32_t sp = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[29], 0));
    const uint32_t gp = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[28], 0));
    const uint32_t a0 = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[4], 0));
    const uint32_t a1 = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[5], 0));
    const uint32_t a2 = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[6], 0));
    const uint32_t a3 = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[7], 0));
    const uint32_t s0 = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[16], 0));
    const uint32_t s1 = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[17], 0));
    const uint32_t v0 = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[2], 0));
    const uint32_t v1 = static_cast<uint32_t>(_mm_extract_epi32(ctx->r[3], 0));

    auto readGuestU32At = [rdram](uint32_t addr, uint32_t &out) -> bool
    {
        // TODO this !rdram exist only because of test fix those test later
        if (!rdram || addr > PS2_RAM_SIZE - sizeof(uint32_t))
        {
            out = 0u;
            return false;
        }

        std::memcpy(&out, rdram + addr, sizeof(uint32_t));
        return true;
    };

    auto readGuestU32Offset = [&readGuestU32At](uint32_t base, uint32_t offset, uint32_t &out) -> bool
    {
        if (base > PS2_RAM_SIZE - sizeof(uint32_t) || offset > PS2_RAM_SIZE - sizeof(uint32_t) - base)
        {
            out = 0u;
            return false;
        }

        return readGuestU32At(base + offset, out);
    };

    uint32_t a0Word0 = 0u;
    uint32_t a0Word4 = 0u;
    uint32_t a0Word8 = 0u;
    uint32_t a0WordC = 0u;
    const bool a0Readable =
        readGuestU32Offset(a0, 0x00u, a0Word0) &&
        readGuestU32Offset(a0, 0x04u, a0Word4) &&
        readGuestU32Offset(a0, 0x08u, a0Word8) &&
        readGuestU32Offset(a0, 0x0cu, a0WordC);

    uint32_t s0Word0 = 0u;
    uint32_t s0Word4 = 0u;
    uint32_t s0Word8 = 0u;
    uint32_t s0WordC = 0u;
    const bool s0Readable =
        readGuestU32Offset(s0, 0x00u, s0Word0) &&
        readGuestU32Offset(s0, 0x04u, s0Word4) &&
        readGuestU32Offset(s0, 0x08u, s0Word8) &&
        readGuestU32Offset(s0, 0x0cu, s0WordC);

    uint32_t recordWord0 = 0u;
    uint32_t recordWord4 = 0u;
    uint32_t recordWord8 = 0u;
    uint32_t recordWordC = 0u;
    const bool recordReadable =
        s0Readable && s0Word4 != 0u &&
        readGuestU32Offset(s0Word4, 0x00u, recordWord0) &&
        readGuestU32Offset(s0Word4, 0x04u, recordWord4) &&
        readGuestU32Offset(s0Word4, 0x08u, recordWord8) &&
        readGuestU32Offset(s0Word4, 0x0cu, recordWordC);

    uint32_t vtableSlot0 = 0u;
    uint32_t vtableSlot4 = 0u;
    uint32_t vtableSlot8 = 0u;
    uint32_t vtableSlotC = 0u;
    const bool vtableReadable =
        a0Readable && a0Word0 != 0u &&
        readGuestU32Offset(a0Word0, 0x00u, vtableSlot0) &&
        readGuestU32Offset(a0Word0, 0x04u, vtableSlot4) &&
        readGuestU32Offset(a0Word0, 0x08u, vtableSlot8) &&
        readGuestU32Offset(a0Word0, 0x0cu, vtableSlotC);

    if (firstReport)
    {
        std::ostringstream oss;
        oss << "[guest-branch:missing-target] kind=" << describeGuestBranchKind(kind)
            << " op=" << (debugName ? debugName : "<unknown>")
            << " source=0x" << std::hex << sourcePc
            << " target=0x" << targetPc
            << " pc=0x" << pc
            << " ra=0x" << ra
            << " sp=0x" << sp
            << " gp=0x" << gp
            << " a0=0x" << a0
            << " a1=0x" << a1
            << " a2=0x" << a2
            << " a3=0x" << a3
            << " s0=0x" << s0
            << " s1=0x" << s1
            << " v0=0x" << v0
            << " v1=0x" << v1
            << " a0Readable=" << (a0Readable ? "yes" : "no")
            << " a0[0]=0x" << a0Word0
            << " a0[4]=0x" << a0Word4
            << " a0[8]=0x" << a0Word8
            << " a0[c]=0x" << a0WordC
            << " s0Readable=" << (s0Readable ? "yes" : "no")
            << " s0[0]=0x" << s0Word0
            << " s0[4]=0x" << s0Word4
            << " s0[8]=0x" << s0Word8
            << " s0[c]=0x" << s0WordC
            << " recordReadable=" << (recordReadable ? "yes" : "no")
            << " record[0]=0x" << recordWord0
            << " record[4]=0x" << recordWord4
            << " record[8]=0x" << recordWord8
            << " record[c]=0x" << recordWordC
            << " vtableReadable=" << (vtableReadable ? "yes" : "no")
            << " vtbl[0]=0x" << vtableSlot0
            << " vtbl[4]=0x" << vtableSlot4
            << " vtbl[8]=0x" << vtableSlot8
            << " vtbl[c]=0x" << vtableSlotC
            << " codeRegion=" << (m_memory.isCodeAddress(targetPc) ? "yes" : "no")
            << " policy=" << static_cast<uint32_t>(policy)
            << " trace=" << formatDispatchHistory()
            << std::dec;

        static std::mutex s_missingFunctionLogMutex;
        {
            std::lock_guard<std::mutex> lock(s_missingFunctionLogMutex);
            std::cerr << oss.str() << std::endl;
        }
    }

    if (firstReport && policy == MissingFunctionPolicy::BreakOnce)
    {
#if defined(_MSC_VER)
        __debugbreak();
#endif // TODO others breakpoints
    }

    if (ctx)
    {
        ctx->pc = targetPc;
    }

    if (policy == MissingFunctionPolicy::Stop)
    {
        requestStop();
    }
}

namespace
{
// Cache of the last successfully-opened DQ8 file's real lba/size (see
// project memory, 2026-08-27), set by the SIF open-reply fix and consumed
// both by the SIF read-reply fix and the func_11C1F0 buffer-registration
// hook below. Deliberately simple: scoped narrowly to this single
// client/recv_buf chain, where open is always immediately followed by its
// own read(s) with no interleaving of a different file -- confirmed via
// live testing this session. Not a general per-file-descriptor cache.
std::atomic<uint32_t> s_lastOpenedFileSize{0u};
std::atomic<uint32_t> s_lastOpenedFileLba{0u};
}

bool PS2Runtime::dispatchGuestBranch(uint8_t *rdram,
                                     R5900Context *ctx,
                                     uint32_t targetPc,
                                     uint32_t sourcePc,
                                     uint32_t fallthroughPc,
                                     GuestBranchKind kind,
                                     const char *debugName)
{
    ctx->pc = targetPc;
    const bool isCall = (kind == GuestBranchKind::DirectCall || kind == GuestBranchKind::IndirectCall);
    uint32_t sif12bcd4ClientPtr = 0u;

    // DIAGNOSTIC (see project memory, 2026-08-26): find the actual
    // indirect-jump/call instruction responsible for thread 1's crash into
    // 0x250ca4 (a mid-function label inside the heap allocator FUN_00250b80,
    // not a valid call/jump target) -- dump sourcePc/kind and the full
    // register file at the exact moment this target is dispatched, so the
    // offending instruction and the register that carried the bad value can
    // be identified by reading the generated code at sourcePc.
    if (targetPc == 0x250ca4u)
    {
        static std::atomic<uint32_t> s_loggedBadJumpTo250ca4{0u};
        if (s_loggedBadJumpTo250ca4.fetch_add(1u, std::memory_order_relaxed) < 10u)
        {
            std::cerr << "[bad-jump-250ca4] source=0x" << std::hex << sourcePc
                      << " kind=" << describeGuestBranchKind(kind)
                      << " name=" << (debugName ? debugName : "?")
                      << " nestedCallDepth=" << std::dec << m_nestedCallDepth << std::hex
                      << " ra=0x" << getRegU32(ctx, 31)
                      << " sp=0x" << getRegU32(ctx, 29)
                      << " gp=0x" << getRegU32(ctx, 28)
                      << " v0=0x" << getRegU32(ctx, 2)
                      << " v1=0x" << getRegU32(ctx, 3)
                      << " a0=0x" << getRegU32(ctx, 4)
                      << " a1=0x" << getRegU32(ctx, 5)
                      << " a2=0x" << getRegU32(ctx, 6)
                      << " a3=0x" << getRegU32(ctx, 7)
                      << " t0=0x" << getRegU32(ctx, 8)
                      << " t1=0x" << getRegU32(ctx, 9)
                      << " s0=0x" << getRegU32(ctx, 16)
                      << " s1=0x" << getRegU32(ctx, 17)
                      << " s2=0x" << getRegU32(ctx, 18)
                      << " t9=0x" << getRegU32(ctx, 25)
                      << std::dec << std::endl;
        }
    }

    {
        static std::atomic<int64_t> s_lastHeartbeatMs{0};
        const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count();
        int64_t last = s_lastHeartbeatMs.load(std::memory_order_relaxed);
        if (nowMs - last >= 1000 &&
            s_lastHeartbeatMs.compare_exchange_strong(last, nowMs, std::memory_order_relaxed))
        {
            std::cerr << "[pc-heartbeat] t=" << nowMs << " pc=0x" << std::hex << targetPc
                       << " source=0x" << sourcePc << std::dec << std::endl;
        }
    }

    // EXPERIMENTAL FIX: func_11A588 (see project memory, 2026-08-25) is DQ8's
    // own inlined SIF RPC bind implementation -- it creates a fresh semaphore,
    // sends a SIF_CMD_RPC_BIND packet via func_119A30/func_119D30 (DQ8's own
    // low-level SIF send routines, not our syscall layer, so our runtime
    // never gets a chance to signal completion), then WaitSema()s on that
    // semaphore forever waiting for an IOP response that never arrives.
    // Rather than replicate DQ8's own low-level SIF packet-send protocol,
    // pre-signal the exact semaphore it's about to wait on -- the semaphore
    // id is already in a0 at this call site (confirmed empirically) -- so
    // its own WaitSema call succeeds immediately, exactly as if the IOP had
    // just responded. This runs every time this call site is hit (not just
    // once), since a fresh semaphore is created per bind attempt.
    // DIAGNOSTIC (see project memory, 2026-08-25): FUN_001641C0 (called
    // from FUN_00160b00 at 0x160d44, well after thread 3 is created) is a
    // sync/teardown routine for thread 3's semaphore pair, gated by a guard
    // read from [gp-0x7088] at its very top -- if that guard is false, the
    // whole thread-3 signal-and-wait sequence is skipped silently. Checking
    // its actual value at the call site to confirm this is why semaphore
    // 37 is never signaled.
    if (sourcePc >= 0x1693b0u && sourcePc < 0x169744u)
    {
        static std::atomic<uint32_t> s_loggedInner{0u};
        if (s_loggedInner.fetch_add(1u, std::memory_order_relaxed) < 40u)
        {
            std::cerr << "[fun1693b0-inner] source=0x" << std::hex << sourcePc
                      << " target=0x" << targetPc << std::dec << std::endl;
        }
    }
    if (sourcePc >= 0x1690e0u && sourcePc < 0x1693b0u)
    {
        static std::atomic<uint32_t> s_loggedInner2{0u};
        if (s_loggedInner2.fetch_add(1u, std::memory_order_relaxed) < 40u)
        {
            std::cerr << "[fun1690e0-inner] source=0x" << std::hex << sourcePc
                      << " target=0x" << targetPc << std::dec << std::endl;
        }
    }
    if (sourcePc >= 0x177310u && sourcePc < 0x1777d4u)
    {
        static std::atomic<uint32_t> s_loggedInner3{0u};
        if (s_loggedInner3.fetch_add(1u, std::memory_order_relaxed) < 60u)
        {
            int curPrio = -1, curId = -999;
            if (m_eeScheduler)
            {
                curId = m_eeScheduler->currentThreadId();
                const EeKernelSnapshot snap = m_eeScheduler->snapshot();
                for (const EeThreadSnapshot &t : snap.threads)
                {
                    if (t.id == curId) { curPrio = t.currentPriority; break; }
                }
            }
            std::cerr << "[fun177310-inner] source=0x" << std::hex << sourcePc
                      << " target=0x" << targetPc << std::dec
                      << " threadId=" << curId << " priority=" << curPrio
                      << std::endl;
        }
    }

    if (sourcePc == 0x160ce4u || sourcePc == 0x160d04u || sourcePc == 0x160d0cu ||
        sourcePc == 0x160d14u || sourcePc == 0x160d1cu || sourcePc == 0x160d28u ||
        sourcePc == 0x160d3cu)
    {
        static std::atomic<uint32_t> s_loggedCheckpoint{0u};
        if (s_loggedCheckpoint.fetch_add(1u, std::memory_order_relaxed) < 20u)
        {
            std::cerr << "[fun160b00-checkpoint] source=0x" << std::hex << sourcePc
                      << " target=0x" << targetPc << std::dec << std::endl;
        }
    }

    // FIX (see project memory, 2026-08-26): DQ8 calls its own inlined SIF
    // RPC bind routine (func_11A588) from MANY distinct external call sites
    // to bind different IOP modules in sequence (confirmed: 0x12bcd4 with
    // a1=0x80000100, 0x12bd28 with a1=0x80000101, likely more elsewhere).
    // Each caller independently re-checks its OWN client struct's
    // SifRpcClientData_t::server field (offset 0x24) after the call and
    // retries its whole delay+bind sequence forever if it's still NULL. The
    // existing 2026-08-25 fix (gated on func_11A588's own internal WaitSema
    // call site, sourcePc==0x11a664, using register $17 as the client
    // pointer) does not reliably resolve to the SAME client struct the
    // external caller re-checks (confirmed empirically for the 0x12bcd4
    // site: infinite retry until fixed here instead). Rather than add a new
    // per-call-site gate for every module DQ8 binds, generalize: capture
    // a0 (the client struct pointer) on ANY call into func_11A588 and patch
    // its server field after the call returns, regardless of caller.
    //
    // DIAGNOSTIC (see project memory, 2026-08-26): DQ8's own inlined SIF
    // bind (func_11A588) allocates a generic 64-byte pool slot (func_119FA8)
    // and sends its ENTIRE contents as the bind request payload via
    // func_119B68(a0=0x80000009 [SIF_CMD_RPC_BIND], a1=bufferPtr, a2=0x40).
    // Our runtime's IOP subsystem has real (if stubbed) service handlers
    // (dbcman, mcserv, libsd, etc, each with a known SID like dbcman's
    // 0x80001300) but NOTHING today ever routes DQ8's own raw SIF sends to
    // them (confirmed: zero "[ps2xIOP]"/"[DBCMAN:stub]" log lines across the
    // ENTIRE day's testing) -- the existing presignal fixes only fake the
    // completion semaphore, never the real service dispatch, so every bind
    // and call "succeeds" but carries no real (even stubbed) response data.
    // Dump the full 64-byte buffer for every observed bind send to find
    // exactly where the target SID lives in DQ8's own packet layout, as a
    // prerequisite for properly wiring this to the real IopSubsystem.
    if (targetPc == 0x119b68u && getRegU32(ctx, 4) == 0x80000009u && rdram)
    {
        const uint32_t bufPtr = getRegU32(ctx, 5) & 0x1FFFFFFFu;
        static std::atomic<uint32_t> s_loggedBindPacket{0u};
        if (s_loggedBindPacket.fetch_add(1u, std::memory_order_relaxed) < 30u)
        {
            std::ostringstream oss;
            oss << "[bind-packet-dump] source=0x" << std::hex << sourcePc
                << " bufPtr=0x" << bufPtr << " words=";
            if (bufPtr <= PS2_RAM_SIZE - 64u)
            {
                for (uint32_t i = 0; i < 16u; ++i)
                {
                    uint32_t word = 0u;
                    std::memcpy(&word, rdram + bufPtr + i * 4u, sizeof(word));
                    oss << "0x" << word << " ";
                }
            }
            else
            {
                oss << "(out of range)";
            }
            std::cerr << oss.str() << std::dec << std::endl;
        }

        // FIX (see project memory, 2026-08-27): func_119FA8 (the 64-byte SIF
        // packet pool DQ8's own bind/call implementations allocate from,
        // confirmed via full read of its scan-for-free-slot logic) never has
        // its slots freed anywhere in DQ8's own code -- real hardware would
        // free a slot once the IOP signals completion, which we never
        // simulate. Every bind (and every call, see the matching fix below)
        // permanently consumes one slot, so the fixed-capacity pool
        // eventually exhausts, after which func_119FA8 returns NULL and
        // func_11A588/func_11A768 fail immediately at the allocation step --
        // this was empirically proven to be the direct cause of a late-boot
        // infinite bind-retry loop (FUN_0012a990, SID 0x80000595). Clear bit
        // 0 of the slot's header (slot+0x10) -- confirmed via direct read of
        // func_119FA8 to be exactly the "in use" flag the scanner checks --
        // to free it back to the pool right after its one-and-only send.
        if (bufPtr <= PS2_RAM_SIZE - 0x14u)
        {
            uint32_t flags = 0u;
            std::memcpy(&flags, rdram + bufPtr + 0x10u, sizeof(flags));
            flags &= ~1u;
            std::memcpy(rdram + bufPtr + 0x10u, &flags, sizeof(flags));
        }
    }

    // DIAGNOSTIC (see project memory, 2026-08-26): the matching CALL-side
    // dump. DQ8's inlined SIF call (func_11A768) sends via the same
    // func_119B68(a0=0x8000000A [SIF_CMD_RPC_CALL], a1=bufferPtr, a2=0x40)
    // primitive. Packet layout matches the real SifCallRpc(client,
    // rpc_number, mode, send_buf, send_size, recv_buf, recv_size, ...)
    // parameter order: word[7] (+0x1c) = the caller's client struct pointer
    // (the SAME object address passed to func_11A588 at bind time -- usable
    // to manually correlate a call back to whichever bind established it),
    // word[8] (+0x20) = rpc_number (the actual function being requested on
    // the target service), word[9] (+0x24) = send_size, word[10] (+0x28) =
    // recv_buf, word[11] (+0x2c) = recv_size.
    if (targetPc == 0x119b68u && getRegU32(ctx, 4) == 0x8000000au && rdram)
    {
        const uint32_t bufPtr = getRegU32(ctx, 5) & 0x1FFFFFFFu;
        static std::atomic<uint32_t> s_loggedCallPacket{0u};
        if (s_loggedCallPacket.fetch_add(1u, std::memory_order_relaxed) < 2000u)
        {
            std::ostringstream oss;
            oss << "[call-packet-dump] source=0x" << std::hex << sourcePc
                << " bufPtr=0x" << bufPtr << " words=";
            if (bufPtr <= PS2_RAM_SIZE - 64u)
            {
                for (uint32_t i = 0; i < 16u; ++i)
                {
                    uint32_t word = 0u;
                    std::memcpy(&word, rdram + bufPtr + i * 4u, sizeof(word));
                    oss << "0x" << word << " ";
                }
            }
            else
            {
                oss << "(out of range)";
            }
            std::cerr << oss.str() << std::dec << std::endl;
        }

        // FIX (see project memory, 2026-08-27): same pool-exhaustion fix as
        // the bind side above -- func_11A768 sends the SAME pool slot twice
        // (a queue-reserve probe then the real dispatch), so this fires at
        // both send sites; clearing an already-cleared bit is a harmless
        // no-op, so freeing at both is safe.
        if (bufPtr <= PS2_RAM_SIZE - 0x14u)
        {
            uint32_t flags = 0u;
            std::memcpy(&flags, rdram + bufPtr + 0x10u, sizeof(flags));
            flags &= ~1u;
            std::memcpy(rdram + bufPtr + 0x10u, &flags, sizeof(flags));
        }
    }

    if (targetPc == 0x11a588u)
    {
        static std::atomic<uint32_t> s_loggedSifBindGeneric{0u};
        const uint32_t nSifBindGeneric = s_loggedSifBindGeneric.fetch_add(1u, std::memory_order_relaxed);
        if (nSifBindGeneric < 100u)
        {
            std::cerr << "[sifbind-generic] source=0x" << std::hex << sourcePc
                      << " a0=0x" << getRegU32(ctx, 4)
                      << " a1=0x" << getRegU32(ctx, 5) << std::dec << std::endl;
        }

        // NOTE (see project memory, 2026-08-26): the actual server-field fix
        // for this call site is applied AFTER the nested call returns (see
        // near targetFn(rdram, ctx, this) below) -- func_11A588 evidently
        // reinitializes/zeroes its client struct as part of its own setup,
        // so writing here (before the call) gets silently overwritten.
        sif12bcd4ClientPtr = getRegU32(ctx, 4) & 0x1FFFFFFFu;
    }

    if (targetPc == 0x1641c0u)
    {
        static std::atomic<uint32_t> s_loggedGuard{0u};
        if (s_loggedGuard.fetch_add(1u, std::memory_order_relaxed) < 10u && rdram)
        {
            uint32_t guardVal = 0xdeadbeefu;
            std::memcpy(&guardVal, rdram + 0x3d26e8u, sizeof(guardVal));
            std::cerr << "[thread3-sync-guard] source=0x" << std::hex << sourcePc
                      << " guardValAt0x3d26e8=0x" << guardVal << std::dec << std::endl;
        }
    }

    // DIAGNOSTIC (see project memory, 2026-08-25): does FUN_00160b00 (the
    // same orchestrator that creates worker threads 3/5/7) ever reach its
    // own later call to FUN_00108398 (video-mode setup, guaranteed to call
    // SetGsCrt)? If it's blocked between creating those threads and this
    // call, that would mean the stuck semaphores are a genuine deadlock,
    // not benign idling.
    if (targetPc == 0x108398u)
    {
        static std::atomic<uint32_t> s_loggedVideoModeSetup{0u};
        if (s_loggedVideoModeSetup.fetch_add(1u, std::memory_order_relaxed) < 10u)
        {
            std::cerr << "[video-mode-setup-call] source=0x" << std::hex << sourcePc
                      << " a0=0x" << getRegU32(ctx, 4)
                      << " a1=0x" << getRegU32(ctx, 5)
                      << " a2=0x" << getRegU32(ctx, 6)
                      << " a3=0x" << getRegU32(ctx, 7)
                      << std::dec << std::endl;
        }
    }
    if (targetPc == 0x160b00u && m_eeScheduler)
    {
        static std::atomic<uint32_t> s_loggedOrchestratorEntry{0u};
        if (s_loggedOrchestratorEntry.fetch_add(1u, std::memory_order_relaxed) < 10u)
        {
            std::cerr << "[orchestrator-160b00-entry] source=0x" << std::hex << sourcePc << std::dec
                      << " threadId=" << m_eeScheduler->currentThreadId() << std::endl;
        }
    }

    // DIAGNOSTIC (see project memory, 2026-08-25): has DQ8 ever called
    // SetGsCrt (display mode setup, a hard prerequisite for any visible
    // output) or GsPutIMR by this point? A clean screenshot with the debug
    // panel hidden showed a fully black framebuffer after 45s+ -- checking
    // whether DQ8 has even reached GS/display setup yet.
    if (targetPc == 0x116420u)
    {
        static std::atomic<uint32_t> s_loggedSetGsCrt{0u};
        if (s_loggedSetGsCrt.fetch_add(1u, std::memory_order_relaxed) < 10u)
        {
            std::cerr << "[SetGsCrt-call] source=0x" << std::hex << sourcePc
                      << " a0=0x" << getRegU32(ctx, 4)
                      << " a1=0x" << getRegU32(ctx, 5)
                      << " a2=0x" << getRegU32(ctx, 6)
                      << std::dec << std::endl;
        }
    }
    if (targetPc == 0x116b60u)
    {
        static std::atomic<uint32_t> s_loggedGsPutIMR{0u};
        if (s_loggedGsPutIMR.fetch_add(1u, std::memory_order_relaxed) < 10u)
        {
            std::cerr << "[GsPutIMR-call] source=0x" << std::hex << sourcePc
                      << " a0=0x" << getRegU32(ctx, 4) << std::dec << std::endl;
        }
    }

    // DIAGNOSTIC (see project memory, 2026-08-25): identify the creator of
    // each worker thread (entry, sourcePc of the CreateThread call) so the
    // caller's own code can be inspected for context/subsystem identity --
    // this is how the id=3/37/67 "who signals this" search continues.
    if (targetPc == 0x116620u && rdram)
    {
        static std::atomic<uint32_t> s_loggedCreateThreadGeneric{0u};
        if (s_loggedCreateThreadGeneric.fetch_add(1u, std::memory_order_relaxed) < 40u)
        {
            const uint32_t paramPtr = getRegU32(ctx, 4) & 0x1FFFFFFFu;
            uint32_t entry = 0xdeadbeefu;
            if (paramPtr <= PS2_RAM_SIZE - 8u)
            {
                std::memcpy(&entry, rdram + paramPtr + 4u, sizeof(entry));
            }
            std::cerr << "[createthread-generic] source=0x" << std::hex << sourcePc
                      << " entry=0x" << entry << std::dec << std::endl;
        }
    }

    if (targetPc == 0x116860u && sourcePc == 0x11a664u)
    {
        static std::atomic<uint32_t> s_loggedWaitAt11a664{0u};
        const uint32_t n = s_loggedWaitAt11a664.fetch_add(1u, std::memory_order_relaxed);
        if (n < 10u)
        {
            std::cerr << "[wait-11a664] #" << std::dec << n
                      << " semId=0x" << std::hex << getRegU32(ctx, 4)
                      << " s1(reg17)=0x" << getRegU32(ctx, 17)
                      << " ra=0x" << getRegU32(ctx, 31)
                      << std::dec << std::endl;
        }
        if (m_eeScheduler)
        {
            const int semId = static_cast<int>(getRegU32(ctx, 4));
            const int result = m_eeScheduler->signalSemaphore(semId, false);
            if (n < 10u)
            {
                std::cerr << "[sifbind-presignal] semId=" << semId
                          << " signalResult=" << result << std::endl;
            }
        }

        // EXTENDED FIX (see project memory, 2026-08-25): pre-signaling the
        // semaphore above is only half the picture. func_11A588's own
        // post-wait check (0x12afbc: `beqz v0, ...` after `v0 = [s1+0x24]`)
        // tests SifRpcClientData_t::server -- confirmed via real ps2sdk
        // source (common/include/sifrpc-common.h): the struct is a 16-byte
        // t_SifRpcHeader (pkt_addr/rpc_id/sema_id/mode) followed by
        // command/buf/cbuf/end_function/end_param/server, putting `server`
        // at exactly offset 0x24 -- an exact match for the empirically
        // observed check, giving high confidence in this read. `server` is
        // NULL until the IOP's bind-complete response populates it; since
        // this runtime never delivers that response, it stays NULL forever,
        // so DQ8 spins in a ~1M-cycle delay loop and retries the whole bind
        // indefinitely. Write a placeholder non-NULL pointer here (a small
        // zeroed scratch buffer in the same confirmed-empty region as the
        // pool-init-fix's slot buffer, but not overlapping it) so DQ8 treats
        // the bind as complete and proceeds past this check. `s1` (reg17,
        // the client data pointer) is confirmed available here from the
        // existing [wait-11a664] log above.
        if (rdram)
        {
            constexpr uint32_t kFakeSifServerData = 0x3d4d00u;
            constexpr uint32_t kFakeSifServerDataSize = 128u;
            static std::atomic<bool> s_fakeServerZeroed{false};
            bool expectedZeroed = false;
            if (s_fakeServerZeroed.compare_exchange_strong(expectedZeroed, true))
            {
                std::memset(rdram + kFakeSifServerData, 0, kFakeSifServerDataSize);
            }
            const uint32_t clientPtr = getRegU32(ctx, 17) & 0x1FFFFFFFu;
            if (clientPtr != 0u && clientPtr <= PS2_RAM_SIZE - 0x28u)
            {
                constexpr uint32_t serverFieldOffset = 0x24u;
                uint32_t serverPtr = kFakeSifServerData;
                std::memcpy(rdram + clientPtr + serverFieldOffset, &serverPtr, sizeof(serverPtr));
                if (n < 10u)
                {
                    std::cerr << "[sifbind-server-fix] wrote server=0x" << std::hex << serverPtr
                              << " at client+0x24=0x" << (clientPtr + serverFieldOffset)
                              << std::dec << std::endl;
                }
            }
        }
    }

    // EXPERIMENTAL FIX: FUN_0011a768 (0x11a768-0x11a968, see project memory,
    // 2026-08-25) is DQ8's own inlined SIF RPC *call* implementation (as
    // opposed to func_11A588's *bind*) -- same shape: func_119FA8 (pool
    // alloc) -> func_116820 (CreateSema) -> func_119B68 with a0=0x8000000A
    // (SIF_CMD_RPC_CALL, confirmed against the same constants used for
    // SIF_CMD_RPC_BIND earlier this session) -> WaitSema([s1+8]) here at
    // 0x11a924 -> DeleteSema -> unconditional `v0=0` return. Unlike the bind
    // case, there is no secondary "response ready" struct-field check after
    // the wait (read the full function body -- it falls straight through to
    // the epilogue), so only the semaphore pre-signal should be needed here.
    // DIAGNOSTIC (see project memory, 2026-08-25): confirm whether
    // FUN_0025a9b0 (VBlank-End handler)'s iPollSema/SignalSema pair at
    // 0x25a9e4/0x25a9fc actually targets and reaches the same semaphore id
    // FUN_002592c0 is blocked in WaitSema on -- both read a0 from the same
    // [gp-0x7464] global, so in principle they must match, but this
    // confirms it empirically with the actual runtime semaphore id.
    if (targetPc == 0x116860u && sourcePc == 0x2592d0u)
    {
        static std::atomic<uint32_t> s_loggedWaitSemId{0u};
        if (s_loggedWaitSemId.fetch_add(1u, std::memory_order_relaxed) < 5u)
        {
            std::cerr << "[worker-wait-semid] FUN_002592c0 about to WaitSema semId=0x"
                      << std::hex << getRegU32(ctx, 4) << std::dec << std::endl;
        }
    }
    if (targetPc == 0x116860u && (sourcePc == 0x117560u || sourcePc == 0x1643b4u || sourcePc == 0x16979cu))
    {
        static std::atomic<uint32_t> s_loggedOtherWaitSemId{0u};
        if (s_loggedOtherWaitSemId.fetch_add(1u, std::memory_order_relaxed) < 15u)
        {
            std::cerr << "[other-worker-wait-semid] source=0x" << std::hex << sourcePc
                      << " semId=0x" << getRegU32(ctx, 4) << std::dec << std::endl;
        }
    }
    if (targetPc == 0x116880u && sourcePc == 0x25a9e4u)
    {
        static std::atomic<uint32_t> s_loggedPollSemId{0u};
        if (s_loggedPollSemId.fetch_add(1u, std::memory_order_relaxed) < 10u)
        {
            std::cerr << "[vblank-poll-semid] iPollSema semId=0x"
                      << std::hex << getRegU32(ctx, 4) << std::dec << std::endl;
        }
    }
    if (targetPc == 0x116850u && sourcePc == 0x25a9fcu)
    {
        static std::atomic<uint32_t> s_loggedVblankSignal{0u};
        if (s_loggedVblankSignal.fetch_add(1u, std::memory_order_relaxed) < 10u)
        {
            std::cerr << "[vblank-signal-semid] iSignalSema semId=0x"
                      << std::hex << getRegU32(ctx, 4) << std::dec << std::endl;
        }
    }

    // FIX (see project memory, 2026-08-27): func_11C1F0 registers a
    // destination buffer (a1) and size (a2) for the just-opened file's real
    // content, then only waits on an always-trivially-satisfied mutex
    // (0x39102C, initCount=1) -- it never itself issues a SIF call, meaning
    // it's designed to receive data delivered asynchronously by real IOP
    // firmware (an unsolicited DMA into this registered buffer) that this
    // runtime has no mechanism to produce, since we only intercept/answer
    // DQ8's own direct SIF-call construction, not actual IOP execution.
    // Confirmed via a live dump that neither of the two SIF read calls that
    // precede this (FUN_0011bfb0, rpc_number==4) ever carry a real
    // destination pointer -- field 0x10 of the shared send buffer stayed 0
    // for both. This synthesizes that missing delivery directly: at the
    // exact point the guest registers the buffer, copy the real disc bytes
    // for the just-opened file (cached lba/size from the open-reply fix)
    // straight into it via Ps2DiscFs.
    if (targetPc == 0x11c1f0u && sourcePc == 0x164904u && rdram)
    {
        const uint32_t destBuf = getRegU32(ctx, 5) & 0x1FFFFFFFu;
        const uint32_t destSize = getRegU32(ctx, 6);
        const uint32_t lba = s_lastOpenedFileLba.load(std::memory_order_relaxed);
        const uint32_t cachedSize = s_lastOpenedFileSize.load(std::memory_order_relaxed);
        static std::atomic<uint32_t> s_loggedDataDeliveryCount{0u};
        Ps2DiscFs *fs = (lba != 0u && cachedSize != 0u && destBuf != 0u &&
                         destSize <= cachedSize && destBuf <= PS2_RAM_SIZE - destSize)
                            ? discFs()
                            : nullptr;
        if (fs)
        {
            const std::vector<uint8_t> bytes = fs->ReadSectors(lba, destSize);
            if (bytes.size() == destSize)
            {
                std::memcpy(rdram + destBuf, bytes.data(), destSize);
            }
            if (s_loggedDataDeliveryCount.fetch_add(1u, std::memory_order_relaxed) < 100u)
            {
                std::cerr << "[sifcall-data-delivery] destBuf=0x" << std::hex << destBuf
                          << " destSize=0x" << destSize << " lba=" << std::dec << lba
                          << " bytesCopied=" << bytes.size() << std::endl;
            }
        }
        else if (s_loggedDataDeliveryCount.fetch_add(1u, std::memory_order_relaxed) < 100u)
        {
            std::cerr << "[sifcall-data-delivery-skip] destBuf=0x" << std::hex << destBuf
                      << " destSize=0x" << destSize << " lba=0x" << lba
                      << " cachedSize=0x" << cachedSize << std::dec << std::endl;
        }
    }

    // TEMPORARY DIAGNOSTIC (2026-08-27): which of the 4 known call sites
    // (0x100354, 0x1085bc, 0x162174, 0x1647e0) actually invokes FUN_0011bba8
    // (the open routine) during boot, and with what a0 (file-slot index
    // passed through to func_11B100's table lookup)?
    if (targetPc == 0x11bba8u)
    {
        static std::atomic<uint32_t> s_loggedOpenCallSite{0u};
        if (s_loggedOpenCallSite.fetch_add(1u, std::memory_order_relaxed) < 100u)
        {
            std::cerr << "[fun-open-callsite] source=0x" << std::hex << sourcePc
                      << " a0(reg4)=0x" << getRegU32(ctx, 4)
                      << " a1(reg5)=0x" << getRegU32(ctx, 5)
                      << std::dec << std::endl;
        }
    }

    // TEMPORARY DIAGNOSTIC (2026-08-27): does 0x3D8768 (the seed target for
    // func_11B8B0's first comparison) actually still hold "3000" at the
    // moment of the check? Verifying directly since the seed fix didn't
    // clear the 0x11bc2c failure path as expected.
    if (targetPc == 0x11b8b0u && rdram)
    {
        uint32_t val3d8768 = 0u, val390f6c = 0u, ptr391030 = 0u, val391030Deref = 0u;
        std::memcpy(&val3d8768, rdram + 0x3d8768u, sizeof(val3d8768));
        std::memcpy(&val390f6c, rdram + 0x390f6cu, sizeof(val390f6c));
        std::memcpy(&ptr391030, rdram + 0x391030u, sizeof(ptr391030));
        const uint32_t ptr391030Phys = ptr391030 & 0x1FFFFFFFu;
        if (ptr391030Phys <= PS2_RAM_SIZE - 4u)
        {
            std::memcpy(&val391030Deref, rdram + ptr391030Phys, sizeof(val391030Deref));
        }
        static std::atomic<uint32_t> s_loggedGateVals{0u};
        if (s_loggedGateVals.fetch_add(1u, std::memory_order_relaxed) < 30u)
        {
            std::cerr << "[fopen-11b8b0-entry] val3d8768=0x" << std::hex << val3d8768
                      << " val390f6c=0x" << val390f6c
                      << " ptr391030=0x" << ptr391030
                      << " val391030Deref=0x" << val391030Deref << std::dec << std::endl;
        }
    }

    // TEMPORARY DIAGNOSTIC (2026-08-27): FUN_0011bba8 (the file-open
    // function) checks a fixed global flag right after its own call to
    // func_11B010 returns -- both func_11A768 and func_11B010 have been
    // confirmed (by full read) to unconditionally return 0 on success, so
    // the address dereferenced here is always exactly `s4` (0x3D0000 +
    // 0x7C80 = 0x3D7C80), a SINGLE fixed global, not a per-open index.
    // Logging its value to determine whether this flag is what actually
    // gates success (and whether/when it's ever nonzero), since a zero-fill
    // reply fix worked once but not reliably in a longer run.
    // TEMPORARY DIAGNOSTIC (2026-08-27): func_11B6A8's own s0 (reg16) at the
    // point it calls func_11AE98 -- right after the SID 0x80000001 bind's
    // server field became nonzero -- should be the SIF client struct itself.
    // Confirmed func_11AE98 is unrelated (it only lazily creates two local
    // semaphores, doesn't touch the client) and the memory mask correctly
    // discards the uncached-alias bit, so client+0/client+4 read here should
    // match what the LATER unaligned copy (0x11b854/58) sees at client+0.
    // Reading both explicitly to pin down exactly which field becomes the
    // observed value 0x8, since the earlier watchpoint only saw the
    // DESTINATION (0x3D8768), not the SOURCE client address itself.
    if (targetPc == 0x11ae98u && sourcePc == 0x11b780u && rdram)
    {
        const uint32_t client = getRegU32(ctx, 16) & 0x1FFFFFFFu;
        uint32_t clientPlus0 = 0u, clientPlus4 = 0u, clientPlus0x24 = 0u;
        if (client <= PS2_RAM_SIZE - 0x28u)
        {
            std::memcpy(&clientPlus0, rdram + client, sizeof(clientPlus0));
            std::memcpy(&clientPlus4, rdram + client + 4u, sizeof(clientPlus4));
            std::memcpy(&clientPlus0x24, rdram + client + 0x24u, sizeof(clientPlus0x24));
        }
        static std::atomic<uint32_t> s_loggedSid1Client{0u};
        if (s_loggedSid1Client.fetch_add(1u, std::memory_order_relaxed) < 50u)
        {
            std::cerr << "[sid1-client] client=0x" << std::hex << client
                      << " +0=0x" << clientPlus0 << " +4=0x" << clientPlus4
                      << " +0x24(server)=0x" << clientPlus0x24 << std::dec << std::endl;
        }
    }

    if (targetPc == 0x11b5b0u && rdram)
    {
        static std::atomic<uint32_t> s_loggedFopenCallSite{0u};
        if (s_loggedFopenCallSite.fetch_add(1u, std::memory_order_relaxed) < 200u)
        {
            std::cerr << "[fopen-callsite] source=0x" << std::hex << sourcePc << std::dec << std::endl;
        }
        if (sourcePc == 0x11bd84u)
        {
            const uint32_t addr = getRegU32(ctx, 2) & 0x1FFFFFFFu;
            uint32_t flagVal = 0xdeadbeefu;
            if (addr <= PS2_RAM_SIZE - 4u)
            {
                std::memcpy(&flagVal, rdram + addr, sizeof(flagVal));
            }
            static std::atomic<uint32_t> s_loggedOpenGateCheck{0u};
            if (s_loggedOpenGateCheck.fetch_add(1u, std::memory_order_relaxed) < 200u)
            {
                std::cerr << "[fopen-gate-check] addr=0x" << std::hex << addr
                          << " value=0x" << flagVal << std::dec << std::endl;
            }
        }
    }

    if (targetPc == 0x116860u && sourcePc == 0x11a924u)
    {
        static std::atomic<uint32_t> s_loggedWaitAt11a924{0u};
        const uint32_t n = s_loggedWaitAt11a924.fetch_add(1u, std::memory_order_relaxed);
        if (n < 2000u)
        {
            // DIAGNOSTIC (2026-08-27): checking whether s2/s3/s4 (send_size/
            // recv_size/recv_buf) still hold the values they had when the
            // call packet was written (see [call-packet-dump]), or whether
            // one of the intervening nested calls (func_119D30/func_119B68/
            // func_116820/func_11A050) clobbers these supposedly callee-saved
            // registers by the time WaitSema is reached. s0 (reg16, the
            // packet's own self-pointer/bufPtr) is the correlator against
            // [call-packet-dump]'s bufPtr= field for the SAME call instance.
            std::cerr << "[wait-11a924] #" << std::dec << n
                      << " semId=0x" << std::hex << getRegU32(ctx, 4)
                      << " s0(reg16,bufPtr)=0x" << getRegU32(ctx, 16)
                      << " s1(reg17)=0x" << getRegU32(ctx, 17)
                      << " s2(reg18,sendSize)=0x" << getRegU32(ctx, 18)
                      << " s3(reg19,recvSize)=0x" << getRegU32(ctx, 19)
                      << " s4(reg20,recvBuf)=0x" << getRegU32(ctx, 20)
                      << std::dec << std::endl;
        }

        // EXPERIMENTAL FIX (see project memory, 2026-08-27): FUN_0011a768's
        // own body never reads recv_buf itself -- it just WaitSema/DeleteSema
        // and returns 0 -- so the existing presignal-only fix leaves recv_buf
        // as stale/zeroed garbage that DQ8's OWN caller (one frame up) then
        // reads as if it were a real IOP reply.
        //
        // CORRECTED (2026-08-27, was reading s2/s3/s4 registers directly --
        // WRONG): s3 (recv_size at packet-write time) gets legitimately
        // REPURPOSED by the compiled code itself at 0x11a8ac ("addiu $s3,
        // $zero, 0x1", the CreateSema initial-count argument) before we ever
        // reach WaitSema -- proven via a live register dump correlated
        // against [call-packet-dump] by bufPtr (s0/reg16, confirmed NOT
        // clobbered): s2/s4 still matched the packet's send_size/recv_buf,
        // but s3 read back as 0x1 instead of the real recv_size (0x8). The
        // packet buffer itself (pointed to by s0, still live) is the correct,
        // robust source: send_size/recv_buf/recv_size live at fixed offsets
        // +0x24/+0x28/+0x2c within it (confirmed against the packet-dump
        // hook's own field mapping).
        // Narrowly scoped to recv_size==8 (the only shape decoded so far, via
        // CDVDSTM.IRX's sub_1B8) to avoid guessing at the other, still-
        // uncharacterized call shapes. Fabricates a plausible success reply
        // (bytesTransferred=send_size, errorCode=0) purely to test whether
        // this -- not just the semaphore -- is what the 0x3F17B0 entity wait
        // (2026-08-26) is actually blocked on.
        if (rdram)
        {
            const uint32_t bufPtr = getRegU32(ctx, 16) & 0x1FFFFFFFu;
            uint32_t rpcNumber = 0u, sendSize = 0u, recvBuf = 0u, recvSize = 0u;
            if (bufPtr <= PS2_RAM_SIZE - 0x30u)
            {
                std::memcpy(&rpcNumber, rdram + bufPtr + 0x20u, sizeof(rpcNumber));
                std::memcpy(&sendSize, rdram + bufPtr + 0x24u, sizeof(sendSize));
                std::memcpy(&recvBuf, rdram + bufPtr + 0x28u, sizeof(recvBuf));
                std::memcpy(&recvSize, rdram + bufPtr + 0x2cu, sizeof(recvSize));
                recvBuf &= 0x1FFFFFFFu;
            }
            // TEMPORARY DIAGNOSTIC (2026-08-27): unconditional, uncapped
            // check specifically for the client 0x3dd980 / SID 0x80000100
            // call (recv_buf=0x3ddbc0, recv_size=0x80) to prove definitively
            // whether WaitSema is even reached for it, independent of the
            // other capped diagnostics above possibly being exhausted first.
            if (recvBuf == 0x3ddbc0u)
            {
                std::cerr << "[wait-11a924-3dd980] bufPtr=0x" << std::hex << bufPtr
                          << " sendSize=0x" << sendSize << " recvSize=0x" << recvSize
                          << std::dec << std::endl;
            }
            // FIX (see project memory, 2026-08-27): rpc_number==0xff is a
            // DIFFERENT call shape from the rpc_number==0 streaming-read
            // pattern this fix was originally written for, even though both
            // happen to use recv_size==8. Proven via a live register dump at
            // the exact write site (func_11B6A8's unaligned copy, s0=reg16)
            // correlated against this exact client's own captured call
            // packet: our OWN "bytesTransferred=send_size" reply for THIS
            // rpc_number was being copied verbatim into 0x3D8768 (a module-
            // version status field checked by func_11B8B0 against the real
            // ELF-constant string "3000" at 0x390F6C) -- i.e. we were
            // supplying a byte count where the game expects a version
            // string. rpc_number==0xff's reply is that version string.
            if (recvSize == 8u && rpcNumber == 0xffu && recvBuf <= PS2_RAM_SIZE - 8u)
            {
                uint32_t versionString = 0u;
                uint32_t errorCode = 0u;
                std::memcpy(&versionString, rdram + 0x390f6cu, sizeof(versionString));
                std::memcpy(rdram + recvBuf, &versionString, sizeof(versionString));
                std::memcpy(rdram + recvBuf + 4u, &errorCode, sizeof(errorCode));
                static std::atomic<uint32_t> s_loggedVersionReply{0u};
                if (s_loggedVersionReply.fetch_add(1u, std::memory_order_relaxed) < 40u)
                {
                    std::cerr << "[sifcall-version-reply] recvBuf=0x" << std::hex << recvBuf
                              << " versionString=0x" << versionString << std::dec << std::endl;
                }
            }
            else if (recvSize == 8u && recvBuf <= PS2_RAM_SIZE - 8u)
            {
                uint32_t bytesTransferred = sendSize;
                uint32_t errorCode = 0u;
                std::memcpy(rdram + recvBuf, &bytesTransferred, sizeof(bytesTransferred));
                std::memcpy(rdram + recvBuf + 4u, &errorCode, sizeof(errorCode));
                static std::atomic<uint32_t> s_loggedFakeReply{0u};
                if (s_loggedFakeReply.fetch_add(1u, std::memory_order_relaxed) < 2000u)
                {
                    std::cerr << "[sifcall-fake-reply] recvBuf=0x" << std::hex << recvBuf
                              << " bytesTransferred=0x" << bytesTransferred
                              << " errorCode=0x" << errorCode << std::dec << std::endl;
                }
            }
            // FIX (see project memory, 2026-08-27): this is DQ8's actual
            // file-open RPC (FUN_0011bba8 -> func_11B010 -> func_11A768),
            // captured live via [call-packet-dump] (client=0x3d8740,
            // rpc_number=0, send_size=0x418, recv_size=4, recv_buf=
            // 0x3d7c80). No prior branch ever handled recv_size==4, so
            // recv_buf was left holding stale "3000" from the earlier
            // version-check reply -- func_11B010's retry loop only checks
            // the reply's sign bit, so the open "succeeded" purely by
            // coincidence of that stale value's top bit being clear, not
            // because we ever actually answered the call.
            //
            // Read func_11A768 in full to find the real protocol:
            // FUN_0011bba8's fixed send buffer at 0x3D7040 (passed as
            // func_11A768's a3, flushed for DMA via func_119D30, then
            // forwarded to func_119B68) embeds the semaphore id to signal
            // at +0x00 -- the real IOP driver would signal it
            // asynchronously once the actual read completes; this is
            // FUN_0011bba8's *own* completion semaphore (created via
            // CreateSema right before this call), separate from
            // func_11A768's internal call-reply semaphore already
            // presignaled below -- and the null-terminated file path at
            // +0x14 (matching the 0x400-byte path-truncation loop read
            // earlier in FUN_0011bba8). Narrowly gated on rpc_number==0 and
            // this exact recv_buf to avoid misfiring on other, uncharacted
            // recv_size==4 call shapes that might exist elsewhere.
            else if (recvSize == 4u && rpcNumber == 0u && recvBuf == 0x3d7c80u)
            {
                constexpr uint32_t kOpenSendBuf = 0x3D7040u;
                uint32_t semToSignal = 0u;
                std::memcpy(&semToSignal, rdram + kOpenSendBuf, sizeof(semToSignal));
                std::string path;
                for (uint32_t i = 0; i < 0x400u; ++i)
                {
                    const char c = static_cast<char>(rdram[kOpenSendBuf + 0x14u + i]);
                    if (c == '\0')
                    {
                        break;
                    }
                    path.push_back(c);
                }
                std::string lookupPath = path;
                for (const char *prefix : {"cdrom0:", "cdrom1:", "cdrom:"})
                {
                    const size_t prefixLen = std::strlen(prefix);
                    if (lookupPath.size() >= prefixLen &&
                        _strnicmp(lookupPath.c_str(), prefix, prefixLen) == 0)
                    {
                        lookupPath.erase(0, prefixLen);
                        break;
                    }
                }
                while (!lookupPath.empty() && (lookupPath.front() == '\\' || lookupPath.front() == '/'))
                {
                    lookupPath.erase(0, 1);
                }
                uint32_t lba = 0u, size = 0u;
                bool found = false;
                if (Ps2DiscFs *fs = discFs())
                {
                    found = fs->Locate(lookupPath, lba, size);
                }
                const int32_t reply = found ? static_cast<int32_t>(size) : -1;
                std::memcpy(rdram + recvBuf, &reply, sizeof(reply));
                // FIX (see project memory, 2026-08-27): FUN_0011bba8 later
                // does WRITE32(allocatedSlot+0, READ32(destPtr)) where
                // destPtr is a caller-local stack address it embedded in
                // this SAME send buffer at +0x4 -- a second, out-of-band
                // result channel distinct from recvBuf, used to seed the
                // 32-slot file-descriptor table's own +0 field (read
                // verbatim, unmodified, by the later read call). Without
                // this, that field stays at its static-init value of 0.
                // Writing the real LBA here is our best-evidence guess at
                // its intended content (the only other real per-file value
                // we have from Ps2DiscFs); verify live before trusting this
                // further downstream.
                if (found)
                {
                    s_lastOpenedFileSize.store(size, std::memory_order_relaxed);
                    s_lastOpenedFileLba.store(lba, std::memory_order_relaxed);
                    uint32_t destPtr = 0u;
                    std::memcpy(&destPtr, rdram + kOpenSendBuf + 0x4u, sizeof(destPtr));
                    destPtr &= 0x1FFFFFFFu;
                    if (destPtr != 0u && destPtr <= PS2_RAM_SIZE - 4u)
                    {
                        std::memcpy(rdram + destPtr, &lba, sizeof(lba));
                        static std::atomic<uint32_t> s_loggedOpenLbaWrite{0u};
                        if (s_loggedOpenLbaWrite.fetch_add(1u, std::memory_order_relaxed) < 100u)
                        {
                            std::cerr << "[sifcall-open-lba-write] destPtr=0x" << std::hex << destPtr
                                      << " lba=" << std::dec << lba << std::endl;
                        }
                    }
                }
                static std::atomic<uint32_t> s_loggedOpenReply{0u};
                if (s_loggedOpenReply.fetch_add(1u, std::memory_order_relaxed) < 100u)
                {
                    std::cerr << "[sifcall-open-reply] path=\"" << path
                              << "\" lookupPath=\"" << lookupPath << "\" found=" << found
                              << " lba=" << lba << " size=" << size
                              << " semToSignal=" << semToSignal << std::endl;
                }
                if (found && semToSignal != 0u && m_eeScheduler)
                {
                    const int signalResult =
                        m_eeScheduler->signalSemaphore(static_cast<int>(semToSignal), false);
                    std::cerr << "[sifcall-open-signal] semId=" << semToSignal
                              << " signalResult=" << signalResult << std::endl;
                }
            }
            // FIX (see project memory, 2026-08-27): FUN_0011bfb0's read call
            // reuses the exact same client/recv_buf/send_buf shape as the
            // open above, but with rpc_number==4 instead of 0 -- confirmed
            // live via [call-packet-dump] (client=0x3d8740, send_size=0x1c,
            // recv_size=4, recv_buf=0x3d7c80). Same fix shape: read the
            // semaphore id this call embeds at the send buffer's +0x0 (same
            // convention as the open), acknowledge with a non-negative reply
            // (func_11B010's retry loop, shared by both open and read,
            // discards the reply's actual value on the success path -- it
            // only checks the sign bit), and signal completion directly.
            // CORRECTED (see project memory, 2026-08-27): the bare "0" reply
            // this branch originally wrote was NOT harmless -- FUN_0011bfb0's
            // own success return value comes from a SECOND out-of-band
            // channel (READ32(sp+0x30) at its return, fed by the destPtr
            // embedded in this SAME send buffer's +0x4 field, the exact same
            // convention as the open's LBA write), and that value feeds
            // directly into FUN_00164710's size-rounding/allocation call
            // (func_100860). Writing 0 there caused a real, confirmed
            // infinite loop (FUN_0012a670 called 50+ times with byte-for-
            // byte identical arguments -- proven live, not inferred). Reusing
            // the just-opened file's real size (cached from the open branch
            // above) is our best-evidence fix; this still does not copy real
            // file BYTES into any destination buffer, only reports a
            // plausible size -- watch for whether that distinction matters
            // once code that reads the actual content is reached.
            else if (recvSize == 4u && rpcNumber == 4u && recvBuf == 0x3d7c80u)
            {
                constexpr uint32_t kReadSendBuf = 0x3D7040u;
                uint32_t semToSignal = 0u;
                std::memcpy(&semToSignal, rdram + kReadSendBuf, sizeof(semToSignal));
                // CORRECTED (see project memory, 2026-08-27): a literal 0
                // reply passes func_11B010's own sign-bit success check but
                // FAILS a second, separate check FUN_0011bfb0 performs right
                // after -- it re-reads recv_buf through its uncached alias
                // and requires the value to be NONZERO (bnez), taking a
                // hardcoded -0xB error path otherwise. Confirmed live: with
                // reply==0 this branch was always taken, producing -11
                // despite func_11B010 itself returning a clean 0. Use 1
                // (a plain non-negative, non-zero acknowledgement) instead.
                const int32_t reply = 1;
                std::memcpy(rdram + recvBuf, &reply, sizeof(reply));
                const uint32_t cachedSize = s_lastOpenedFileSize.load(std::memory_order_relaxed);
                uint32_t readDestPtr = 0u;
                std::memcpy(&readDestPtr, rdram + kReadSendBuf + 0x4u, sizeof(readDestPtr));
                readDestPtr &= 0x1FFFFFFFu;
                if (cachedSize != 0u && readDestPtr != 0u && readDestPtr <= PS2_RAM_SIZE - 4u)
                {
                    std::memcpy(rdram + readDestPtr, &cachedSize, sizeof(cachedSize));
                }
                uint32_t field0x10 = 0u, field0x14 = 0u;
                std::memcpy(&field0x10, rdram + kReadSendBuf + 0x10u, sizeof(field0x10));
                std::memcpy(&field0x14, rdram + kReadSendBuf + 0x14u, sizeof(field0x14));
                static std::atomic<uint32_t> s_loggedReadReply{0u};
                if (s_loggedReadReply.fetch_add(1u, std::memory_order_relaxed) < 100u)
                {
                    std::cerr << "[sifcall-read-reply] semToSignal=" << semToSignal
                              << " readDestPtr=0x" << std::hex << readDestPtr << std::dec
                              << " cachedSize=" << cachedSize
                              << " field0x10=0x" << std::hex << field0x10
                              << " field0x14=0x" << field0x14 << std::dec << std::endl;
                }
                if (semToSignal != 0u && m_eeScheduler)
                {
                    const int signalResult =
                        m_eeScheduler->signalSemaphore(static_cast<int>(semToSignal), false);
                    std::cerr << "[sifcall-read-signal] semId=" << semToSignal
                              << " signalResult=" << signalResult << std::endl;
                }
            }
            // FIX (see project memory, 2026-08-27): a THIRD call shape,
            // rpc_number==2, reached from the code right after func_11C1F0
            // (send_size=0x20, recv_size=4, same client=0x3d8740/recv_buf=
            // 0x3d7c80/send_buf=0x3d7040 convention as open/read). Traced
            // its caller in full: it registers a free slot in a 32-entry
            // request table at 0x390F98 (previously misidentified as a
            // "retry-budget counter" -- it's actually a general pending-SIF-
            // request slot registry, unrelated to the open/read investigation
            // that first found it), makes this call, checks recv_buf is
            // nonzero via the same uncached-alias trick used by open/read,
            // then WaitSema's on an embedded semaphore only if the found
            // slot index was 0. Same fix shape as the read: acknowledge with
            // a non-negative nonzero reply and signal the embedded
            // semaphore. Real semantics of this specific call are not yet
            // understood beyond "same family as open/read" -- watch for
            // whether a bare acknowledgement is sufficient here too, the way
            // it eventually proved insufficient for the read.
            else if (recvSize == 4u && rpcNumber == 2u && recvBuf == 0x3d7c80u)
            {
                constexpr uint32_t kThirdCallSendBuf = 0x3D7040u;
                uint32_t semToSignal = 0u;
                std::memcpy(&semToSignal, rdram + kThirdCallSendBuf, sizeof(semToSignal));
                const int32_t reply = 1;
                std::memcpy(rdram + recvBuf, &reply, sizeof(reply));
                static std::atomic<uint32_t> s_loggedThirdCallReply{0u};
                if (s_loggedThirdCallReply.fetch_add(1u, std::memory_order_relaxed) < 100u)
                {
                    std::cerr << "[sifcall-rpc2-reply] semToSignal=" << semToSignal << std::endl;
                }
                if (semToSignal != 0u && m_eeScheduler)
                {
                    const int signalResult =
                        m_eeScheduler->signalSemaphore(static_cast<int>(semToSignal), false);
                    std::cerr << "[sifcall-rpc2-signal] semId=" << semToSignal
                              << " signalResult=" << signalResult << std::endl;
                }
            }
            // FIX (see project memory, 2026-08-27): a FOURTH call shape,
            // rpc_number==1 (send_size=0x14 this time), found immediately
            // after investigating the rpc_number==2 wait -- same
            // client/recv_buf/send_buf family, same "create sema, embed id
            // at send_buf+0x0, wait on it after checking recv_buf nonzero
            // via the uncached alias" structure as rpc_number==2 and the
            // read. Same fix.
            else if (recvSize == 4u && rpcNumber == 1u && recvBuf == 0x3d7c80u)
            {
                constexpr uint32_t kFourthCallSendBuf = 0x3D7040u;
                uint32_t semToSignal = 0u;
                std::memcpy(&semToSignal, rdram + kFourthCallSendBuf, sizeof(semToSignal));
                const int32_t reply = 1;
                std::memcpy(rdram + recvBuf, &reply, sizeof(reply));
                static std::atomic<uint32_t> s_loggedFourthCallReply{0u};
                if (s_loggedFourthCallReply.fetch_add(1u, std::memory_order_relaxed) < 100u)
                {
                    std::cerr << "[sifcall-rpc1-reply] semToSignal=" << semToSignal << std::endl;
                }
                if (semToSignal != 0u && m_eeScheduler)
                {
                    const int signalResult =
                        m_eeScheduler->signalSemaphore(static_cast<int>(semToSignal), false);
                    std::cerr << "[sifcall-rpc1-signal] semId=" << semToSignal
                              << " signalResult=" << signalResult << std::endl;
                }
            }
            // EXPERIMENTAL GENERALIZATION (2026-08-27): other call shapes
            // exist beyond the recv_size==8 streaming-read pattern (e.g. a
            // client seen with send_size=recv_size=0x80, and others with
            // recv_size=0) -- their real reply semantics are NOT understood,
            // so guessing at specific field values would risk silently
            // corrupting whatever structure they represent (see project
            // memory's standing caution on this). Zero-filling is the
            // deliberately minimal, most conservative fallback: it is
            // strictly better than the stale garbage a reused, non-zeroed
            // pool slot would otherwise leave behind (our own pool-slot-
            // freeing fix only clears the "in use" bit, not the slot's old
            // contents), and a zeroed reply is a common "no error, no data"
            // convention -- but it is NOT known to be semantically correct
            // for any of these other shapes. Purely to test whether DQ8's
            // own retry logic (e.g. FUN_0011b010's up-to-100-attempt loop)
            // can make forward progress with a deterministic-but-plausibly-
            // wrong reply rather than real garbage.
            else if (recvSize > 8u && recvSize <= 4096u && recvBuf <= PS2_RAM_SIZE - recvSize)
            {
                std::memset(rdram + recvBuf, 0, recvSize);
                static std::atomic<uint32_t> s_loggedGenericFakeReply{0u};
                if (s_loggedGenericFakeReply.fetch_add(1u, std::memory_order_relaxed) < 2000u)
                {
                    std::cerr << "[sifcall-fake-reply-generic] recvBuf=0x" << std::hex << recvBuf
                              << " recvSize=0x" << recvSize << std::dec << std::endl;
                }
            }
        }

        if (m_eeScheduler)
        {
            const int semId = static_cast<int>(getRegU32(ctx, 4));
            const int result = m_eeScheduler->signalSemaphore(semId, false);
            if (n < 10u)
            {
                std::cerr << "[sifcall-presignal] semId=" << semId
                          << " signalResult=" << result << std::endl;
            }
        }
    }

    // REVERTED EXPERIMENT (see project memory, 2026-08-25): tried
    // presignaling three more WaitSema call sites on persistent,
    // $gp-relative global semaphore ids -- FUN_001643a0 (0x1643b4),
    // FUN_002592c0 (0x2592d0), FUN_00169790 (0x16979c) -- each gating a
    // per-iteration worker loop. Unlike the SIF-bind/SIF-call cases (which
    // wait once per invocation and then move on), these are loops that
    // WaitSema on every iteration; presignaling every hit let one of them
    // (0x1643b4) spin as fast as possible forever, starving the scheduler
    // and causing a measured REGRESSION (only 3 threads / ~1.5B eeCycle
    // reached in 60s, versus 7 threads / ~17.5B without this fix). Reverted.
    // These threads are legitimately meant to be woken at a real, bounded
    // rate (likely VSync-adjacent) -- fixing them needs rate-limited
    // signaling (e.g. tied to the existing VSync/timer IRQ delivery, not an
    // unconditional per-hit presignal), not attempted yet.

    if (sourcePc >= 0x12ae98u && sourcePc < 0x12b180u)
    {
        static std::atomic<uint32_t> s_traceFun12ae98{0u};
        const uint32_t n = s_traceFun12ae98.fetch_add(1u, std::memory_order_relaxed);
        if (n < 60u)
        {
            std::cerr << "[trace-12ae98] #" << std::dec << n
                      << " source=0x" << std::hex << sourcePc
                      << " target=0x" << targetPc
                      << " v0=0x" << getRegU32(ctx, 2)
                      << std::dec << std::endl;
        }
    }

    {
        static std::atomic<bool> s_awaitingReturnFrom11a588{false};
        // Only counts as "returned" once sourcePc is outside func_11A588's
        // own body (0x11a588-0x11a6d4) -- calls made *from within* it (the
        // pool allocator, CreateSema, the SIF-bind send, WaitSema, etc.)
        // must not be mistaken for the caller resuming.
        if (s_awaitingReturnFrom11a588.load(std::memory_order_relaxed) &&
            (sourcePc < 0x11a588u || sourcePc >= 0x11a6d4u))
        {
            s_awaitingReturnFrom11a588.store(false, std::memory_order_relaxed);
            static std::atomic<uint32_t> s_returnLogCount{0u};
            const uint32_t n = s_returnLogCount.fetch_add(1u, std::memory_order_relaxed);
            if (n < 15u)
            {
                std::cerr << "[after-11a588-return] #" << std::dec << n
                          << " nextTarget=0x" << std::hex << targetPc
                          << " nextSource=0x" << sourcePc
                          << " v0=0x" << getRegU32(ctx, 2)
                          << std::dec << std::endl;
            }
        }
        if (targetPc == 0x11a588u)
        {
            s_awaitingReturnFrom11a588.store(true, std::memory_order_relaxed);
        }
    }

    if (targetPc == 0x119d30u && sourcePc == 0x12afccu)
    {
        static std::atomic<uint32_t> s_loggedSuccessPath{0u};
        const uint32_t n = s_loggedSuccessPath.fetch_add(1u, std::memory_order_relaxed);
        if (n < 10u)
        {
            std::cerr << "[func11a588-success-path-reached] #" << std::dec << n << std::endl;
        }
    }

    if (targetPc == 0x11a588u)
    {
        static std::atomic<uint32_t> s_loggedCall11a588{0u};
        const uint32_t n = s_loggedCall11a588.fetch_add(1u, std::memory_order_relaxed);
        if (n < 15u)
        {
            std::cerr << "[call-0x11a588] #" << std::dec << n
                      << " source=0x" << std::hex << sourcePc
                      << " a0=0x" << getRegU32(ctx, 4)
                      << " a1=0x" << getRegU32(ctx, 5)
                      << " a2=0x" << getRegU32(ctx, 6)
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x116460u)
    {
        static std::atomic<uint32_t> s_loggedLoadExec{0u};
        const uint32_t n = s_loggedLoadExec.fetch_add(1u, std::memory_order_relaxed);
        if (n < 5u)
        {
            std::cerr << "[call-LoadExecPS2] #" << std::dec << n
                      << " source=0x" << std::hex << sourcePc
                      << std::dec << std::endl;
        }
    }

    if ((targetPc == 0x116840u || targetPc == 0x116850u) && getRegU32(ctx, 4) == 3u)
    {
        static std::atomic<uint32_t> s_loggedSignalSema3{0u};
        const uint32_t n = s_loggedSignalSema3.fetch_add(1u, std::memory_order_relaxed);
        if (n < 20u)
        {
            std::cerr << "[call-signalsema3] #" << std::dec << n
                      << " target=0x" << std::hex << targetPc
                      << " source=0x" << sourcePc
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x116620u && sourcePc == 0x117678u)
    {
        static std::atomic<bool> s_loggedCreateThread{false};
        bool expected = false;
        if (s_loggedCreateThread.compare_exchange_strong(expected, true))
        {
            std::cerr << "[createthread-1175f8] a0(prio)=0x" << std::hex << getRegU32(ctx, 4)
                      << " a1(entry)=0x" << getRegU32(ctx, 5)
                      << " a2(stack)=0x" << getRegU32(ctx, 6)
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x116830u && sourcePc == 0x11768cu)
    {
        static std::atomic<bool> s_loggedCreateThreadFailed{false};
        bool expected = false;
        if (s_loggedCreateThreadFailed.compare_exchange_strong(expected, true))
        {
            std::cerr << "[createthread-1175f8] FAILED, createThreadRetval(a0 here)=0x"
                       << std::hex << getRegU32(ctx, 4) << std::dec << std::endl;
        }
    }

    if (targetPc == 0x117960u && sourcePc == 0x1176acu)
    {
        static std::atomic<bool> s_loggedCreateThreadSucceeded{false};
        bool expected = false;
        if (s_loggedCreateThreadSucceeded.compare_exchange_strong(expected, true))
        {
            std::cerr << "[createthread-1175f8] SUCCEEDED path reached" << std::endl;
        }
    }

    if (targetPc == 0x1211f0u)
    {
        static std::atomic<uint32_t> s_logged1211f0{0u};
        const uint32_t n = s_logged1211f0.fetch_add(1u, std::memory_order_relaxed);
        if (n < 5u)
        {
            uint32_t val = 0xdeadbeefu;
            if (rdram)
            {
                std::memcpy(&val, rdram + 0x392630u, sizeof(val));
            }
            std::cerr << "[call-0x1211f0] #" << std::dec << n
                      << " a0=0x" << std::hex << getRegU32(ctx, 4)
                      << " [0x392630]=0x" << val
                      << " isNegative=" << (static_cast<int32_t>(val) < 0)
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x121078u)
    {
        static std::atomic<uint32_t> s_logged121078{0u};
        const uint32_t n = s_logged121078.fetch_add(1u, std::memory_order_relaxed);
        if (n < 5u)
        {
            const uint32_t t3Mode = m_memory.readIORegister(0x10001810u);
            std::cerr << "[call-0x121078] #" << std::dec << n
                      << " t3Mode=0x" << std::hex << t3Mode
                      << " cmpeBit=" << ((t3Mode & 0x100u) != 0u)
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x135780u && sourcePc == 0x160ba0u)
    {
        static std::atomic<bool> s_loggedBranchNotTaken{false};
        bool expected = false;
        if (s_loggedBranchNotTaken.compare_exchange_strong(expected, true))
        {
            std::cerr << "[branch-160b90-NOT-taken] s0(a1 here)=0x" << std::hex << getRegU32(ctx, 5)
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x164cd0u && sourcePc == 0x160b88u)
    {
        static std::atomic<bool> s_loggedS0{false};
        bool expected = false;
        if (s_loggedS0.compare_exchange_strong(expected, true))
        {
            std::cerr << "[func137010-retval-via-s0] s0(a0 here)=0x" << std::hex << getRegU32(ctx, 4)
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x137010u && sourcePc == 0x160b7cu)
    {
        static std::atomic<bool> s_logged137010{false};
        bool expected = false;
        if (s_logged137010.compare_exchange_strong(expected, true))
        {
            uint32_t argListPtr = 0xdeadbeefu;
            uint32_t deref92 = 0xdeadbeefu;
            uint32_t deref92byte0 = 0xdeadbeefu;
            if (rdram)
            {
                std::memcpy(&argListPtr, rdram + 0x3945d8u, sizeof(argListPtr));
                if (argListPtr != 0u && argListPtr <= PS2_RAM_SIZE - 96u)
                {
                    std::memcpy(&deref92, rdram + argListPtr + 92u, sizeof(deref92));
                    deref92byte0 = deref92 & 0xffu;
                }
            }
            std::cerr << "[call-0x137010] a0=0x" << std::hex << getRegU32(ctx, 4)
                      << " a1=0x" << getRegU32(ctx, 5)
                      << " *(0x3945d8)=0x" << argListPtr
                      << " *(argListPtr+92)=0x" << deref92
                      << " firstByte=0x" << deref92byte0
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x160b00u)
    {
        static std::atomic<bool> s_logged160b00{false};
        bool expected = false;
        if (s_logged160b00.compare_exchange_strong(expected, true))
        {
            std::cerr << "[call-0x160b00] a0=0x" << std::hex << getRegU32(ctx, 4)
                      << " a1=0x" << getRegU32(ctx, 5)
                      << std::dec << std::endl;
        }
    }

    // EXPERIMENTAL FIX: 0x3D6FC0 is a fixed-size kernel-object pool descriptor
    // (see project memory, 2026-08-25) that FUN_0012ae98's retry loop spins
    // forever waiting on, via func_11A588 -> func_119FA8. Four exhaustive
    // searches this session (absolute address, gp-relative address, raw ELF
    // data, and a global value-range write watchpoint) found that NO game
    // code anywhere ever writes to it. func_119FA8's exact shape (scan N
    // fixed-size slots for a free one, encode claimed slots as
    // (index<<16)|5) is generic, low-level kernel-object-pool bookkeeping,
    // not application data -- the working theory is that this is
    // infrastructure the real PS2 BIOS/kernel populates during its own
    // startup, which this runtime skips entirely (it jumps straight to the
    // game's ELF entry point). Pre-populate it here, once, right before
    // FUN_0012ae98 is first reached (i.e. after the guest's own BSS-clear
    // loop at entry_0x100008 has already run, so this write survives).
    // Slot buffer placed at 0x3D7000, safely within the region this
    // session's mem-scan confirmed is otherwise completely unused
    // (0x3D4C50-0x3D8000). 64 slots * 64 bytes = 0x1000 bytes, and a
    // zeroed buffer is already in the correct "all slots free" state
    // (slot flags field bit0 == 0 means free), so only the pool header
    // itself (listBase at +4, count at +8) needs writing.
    if (targetPc == 0x12ae98u)
    {
        static std::atomic<bool> s_poolInitDone{false};
        bool expected = false;
        if (s_poolInitDone.compare_exchange_strong(expected, true))
        {
            constexpr uint32_t kPoolHeader = 0x3d6fc0u;
            constexpr uint32_t kPoolSlots = 0x3d7000u;
            constexpr uint32_t kPoolSlotCount = 64u;
            if (rdram)
            {
                uint32_t listBase = kPoolSlots;
                uint32_t count = kPoolSlotCount;
                std::memcpy(rdram + kPoolHeader + 4u, &listBase, sizeof(listBase));
                std::memcpy(rdram + kPoolHeader + 8u, &count, sizeof(count));
                std::cerr << "[pool-init-fix] wrote listBase=0x" << std::hex << listBase
                          << " count=" << std::dec << count
                          << " at pool 0x" << std::hex << kPoolHeader << std::dec << std::endl;
            }
        }
    }

    if (targetPc == 0x12ae98u)
    {
        static std::atomic<bool> s_dumped{false};
        bool expected = false;
        if (s_dumped.compare_exchange_strong(expected, true))
        {
            constexpr uint32_t kDumpStart = 0x3d0000u;
            constexpr uint32_t kDumpEnd = 0x3d8000u;
            std::cerr << "[mem-scan] scanning 0x" << std::hex << kDumpStart
                      << "-0x" << kDumpEnd << std::dec << std::endl;
            bool inRun = false;
            uint32_t runStart = 0u;
            for (uint32_t addr = kDumpStart; addr < kDumpEnd; addr += 16u)
            {
                if (!rdram || addr > PS2_RAM_SIZE - 16u)
                {
                    break;
                }
                uint32_t words[4] = {0, 0, 0, 0};
                std::memcpy(words, rdram + addr, sizeof(words));
                const bool nonzero = (words[0] || words[1] || words[2] || words[3]);
                if (nonzero && !inRun)
                {
                    inRun = true;
                    runStart = addr;
                }
                else if (!nonzero && inRun)
                {
                    inRun = false;
                    std::cerr << "[mem-scan] populated 0x" << std::hex << runStart
                               << "-0x" << addr << std::dec << std::endl;
                }
            }
            if (inRun)
            {
                std::cerr << "[mem-scan] populated 0x" << std::hex << runStart
                           << "-0x" << kDumpEnd << std::dec << std::endl;
            }
            std::cerr << "[mem-scan] done" << std::endl;
            std::cerr << "[gp-at-12ae98] gp=0x" << std::hex << getRegU32(ctx, 28) << std::dec << std::endl;

            if (m_eeScheduler)
            {
                m_eeScheduler->debugDumpIrqHandlers();
                const EeKernelSnapshot snap = m_eeScheduler->snapshot();
                std::cerr << "[thread-dump] runningThreadId=" << snap.runningThreadId
                          << " threadCount=" << snap.threads.size() << std::endl;
                for (const EeThreadSnapshot &t : snap.threads)
                {
                    std::cerr << "[thread-dump] id=" << t.id
                              << " status=" << static_cast<int>(t.status)
                              << " pc=0x" << std::hex << t.pc
                              << " entry=0x" << t.entry
                              << std::dec
                              << " prio=" << t.currentPriority
                              << " waitReason=" << static_cast<int>(t.waitReason)
                              << " waitId=" << t.waitId
                              << std::endl;
                }
            }
        }
    }

    if (sourcePc == 0x100e14u)
    {
        static std::atomic<uint64_t> s_initTableCallCount{0u};
        const uint64_t n = s_initTableCallCount.fetch_add(1u, std::memory_order_relaxed);
        if (n < 200u)
        {
            std::cerr << "[init-table-call] #" << std::dec << n
                      << " target=0x" << std::hex << targetPc
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x1211d0u)
    {
        static std::atomic<uint64_t> s_targetCallCount{0u};
        const uint64_t n = s_targetCallCount.fetch_add(1u, std::memory_order_relaxed);
        if (n < 30u)
        {
            std::cerr << "[call-0x1211d0] #" << std::dec << n
                      << " source=0x" << std::hex << sourcePc
                      << " a0=0x" << getRegU32(ctx, 4)
                      << " a1=0x" << getRegU32(ctx, 5)
                      << " ra=0x" << getRegU32(ctx, 31)
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x119fa8u)
    {
        static std::atomic<uint64_t> s_poolAllocCount{0u};
        const uint64_t n = s_poolAllocCount.fetch_add(1u, std::memory_order_relaxed);
        if (n < 15u)
        {
            uint32_t poolCount = 0xdeadbeefu;
            uint32_t poolListBase = 0xdeadbeefu;
            const uint32_t poolPtr = getRegU32(ctx, 4) & 0x1FFFFFFFu;
            if (rdram && poolPtr <= PS2_RAM_SIZE - sizeof(uint32_t) - 8u)
            {
                std::memcpy(&poolCount, rdram + poolPtr + 8u, sizeof(uint32_t));
                std::memcpy(&poolListBase, rdram + poolPtr + 4u, sizeof(uint32_t));
            }
            std::cerr << "[pool-alloc-0x119fa8] #" << std::dec << n
                      << " poolPtr=0x" << std::hex << poolPtr
                      << " count=0x" << poolCount
                      << " listBase=0x" << poolListBase
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x121790u)
    {
        static std::atomic<uint64_t> s_fun121790CallCount{0u};
        const uint64_t n = s_fun121790CallCount.fetch_add(1u, std::memory_order_relaxed);
        if (n < 30u)
        {
            std::cerr << "[call-0x121790] #" << std::dec << n
                      << " source=0x" << std::hex << sourcePc
                      << " kind=" << static_cast<int>(kind)
                      << " name=" << (debugName ? debugName : "?")
                      << " a0=0x" << getRegU32(ctx, 4)
                      << " ra=0x" << getRegU32(ctx, 31)
                      << std::dec << std::endl;
        }
    }

    // Every inter-function transfer is also a deterministic EE safe point.
    // Backward edges inside generated functions use eeCheckpointDue(), while
    // this charge bounds straight-line call chains that have no local loop.
    if (m_eeScheduler && m_eeScheduler->checkpointDue(EeScheduler::kGuestDispatchCycles))
    {
        return false;
    }

    if (!isCall)
    {
        if (!hasFunction(targetPc))
        {
            reportMissingFunction(rdram, ctx, targetPc, sourcePc, kind, debugName);
        }

        // DIAGNOSTIC (see project memory, 2026-08-26): a Return (jr $ra) to
        // target 0 with ra==0 is DQ8's convention for "this thread's
        // top-level function is done, terminate" -- but if this happens
        // while nested inside a synchronous C++ call (targetFn(...) at
        // ~line 2101 below), the IMMEDIATE OUTER CALLER's own generated code
        // unconditionally overwrites ctx->pc with its own known fallthrough
        // address right after the nested call returns, silently erasing
        // this signal before the scheduler's top-level loop ever sees
        // ctx->pc==0. Log the current nesting depth to determine whether
        // this specific occurrence is at the true outermost level (where it
        // would correctly propagate) or buried mid-chain (where it would be
        // masked and NOT actually terminate the thread).
        if (kind == GuestBranchKind::Return && targetPc == 0u && m_eeScheduler &&
            m_eeScheduler->currentThreadId() == 1)
        {
            static std::atomic<uint32_t> s_loggedReturnToZero{0u};
            if (s_loggedReturnToZero.fetch_add(1u, std::memory_order_relaxed) < 20u)
            {
                std::cerr << "[return-to-zero] source=0x" << std::hex << sourcePc << std::dec
                          << " nestedCallDepth=" << m_nestedCallDepth << std::endl;
            }
        }

        ctx->pc = targetPc;
        return false;
    }

    if (!hasFunction(targetPc))
    {
        reportMissingFunction(rdram, ctx, targetPc, sourcePc, kind, debugName);

        const MissingFunctionPolicy policy = missingFunctionPolicy();

        if (policy == MissingFunctionPolicy::SkipCallDebug && isCall)
        {
            ctx->pc = fallthroughPc;
            return true;
        }

        if (policy == MissingFunctionPolicy::ContinueToTarget)
        {
            ctx->pc = targetPc;
            return true;
        }

        return false;
    }

    RecompiledFunction targetFn = lookupFunction(targetPc);
    const uint32_t entryPc = ctx->pc;
    const uint32_t sceSifGetRegArg0 = (targetPc == 0x116c30u) ? getRegU32(ctx, 4) : 0u;
    uint32_t cachedClientAt391040Before = 0u;
    if (targetPc == 0x11f020u && rdram)
    {
        std::memcpy(&cachedClientAt391040Before, rdram + 0x391040u, sizeof(cachedClientAt391040Before));
    }
    uint32_t memcmpA0Before = 0u, memcmpA1Before = 0u, memcmpA2Before = 0u;
    uint32_t memcmpBuf0Before = 0u, memcmpBuf1Before = 0u;
    if (targetPc == 0x1325f8u && rdram)
    {
        memcmpA0Before = getRegU32(ctx, 4) & 0x1FFFFFFFu;
        memcmpA1Before = getRegU32(ctx, 5) & 0x1FFFFFFFu;
        memcmpA2Before = getRegU32(ctx, 6);
        if (memcmpA0Before <= PS2_RAM_SIZE - 4u) { std::memcpy(&memcmpBuf0Before, rdram + memcmpA0Before, 4u); }
        if (memcmpA1Before <= PS2_RAM_SIZE - 4u) { std::memcpy(&memcmpBuf1Before, rdram + memcmpA1Before, 4u); }
    }
    ++m_nestedCallDepth;
    targetFn(rdram, ctx, this);
    --m_nestedCallDepth;

    // FIX (see project memory, 2026-08-26): applied AFTER func_11A588
    // returns (writing before the call gets silently overwritten by the
    // function's own client-struct initialization -- confirmed empirically,
    // see sif12bcd4ClientPtr's capture site above). Write the fake non-null
    // SifRpcClientData_t::server pointer (offset 0x24) so the caller at
    // 0x12bce0's `beqz $v1, retry` sees success instead of looping its
    // whole delay+bind sequence forever.
    if (sif12bcd4ClientPtr != 0u && rdram)
    {
        constexpr uint32_t kFakeSifServerData = 0x3d4d00u;
        constexpr uint32_t kFakeSifServerDataSize = 128u;
        static std::atomic<bool> s_fakeServerZeroed2{false};
        bool expectedZeroed2 = false;
        if (s_fakeServerZeroed2.compare_exchange_strong(expectedZeroed2, true))
        {
            std::memset(rdram + kFakeSifServerData, 0, kFakeSifServerDataSize);
        }
        if (sif12bcd4ClientPtr <= PS2_RAM_SIZE - 0x28u)
        {
            constexpr uint32_t serverFieldOffset = 0x24u;
            uint32_t serverPtr = kFakeSifServerData;
            std::memcpy(rdram + sif12bcd4ClientPtr + serverFieldOffset, &serverPtr, sizeof(serverPtr));
            static std::atomic<uint32_t> s_loggedSif12bcd4Fix{0u};
            if (s_loggedSif12bcd4Fix.fetch_add(1u, std::memory_order_relaxed) < 10u)
            {
                std::cerr << "[sifbind-12bcd4-server-fix] wrote server=0x" << std::hex << serverPtr
                          << " at client+0x24=0x" << (sif12bcd4ClientPtr + serverFieldOffset)
                          << std::dec << std::endl;
            }
        }
    }

    // EXPERIMENTAL FIX (see project memory, 2026-08-25): FUN_0011f120
    // (called from FUN_0011f7f8, called from FUN_0011fa20, looped by
    // FUN_00160b00) does a real memcmp([0x3D8C28], [0x390F6C], 4), where
    // 0x390F6C is a fixed ELF constant equal to the ASCII bytes "3000" (a
    // version string, confirmed via [chase-1325f8-call] diagnostic dump --
    // little-endian word 0x30303033 = '3','0','0','0'). 0x3D8C28 is meant
    // to hold a real IOP module-version response this runtime has no real
    // IOP to provide, so it stays at its default zero and the comparison
    // never matches, causing FUN_00160b00's retry loop to spin forever.
    // Same fix pattern as the pool-init-fix: pre-populate the piece of
    // state a real BIOS/IOP handshake would have set, once, before this
    // loop can ever be reached (gated on FUN_001609c0's entry, which is
    // this loop's own setup/caller function).
    if (targetPc == 0x1609c0u)
    {
        static std::atomic<bool> s_moduleVersionSeeded{false};
        bool expected = false;
        if (s_moduleVersionSeeded.compare_exchange_strong(expected, true) && rdram)
        {
            uint32_t expectedVersion = 0u;
            std::memcpy(&expectedVersion, rdram + 0x390f6cu, sizeof(expectedVersion));
            std::memcpy(rdram + 0x3d8c28u, &expectedVersion, sizeof(expectedVersion));
            std::cerr << "[module-version-fix] wrote 0x" << std::hex << expectedVersion
                      << " to 0x3d8c28" << std::dec << std::endl;
        }
    }

    // REVERTED EXPERIMENT (see project memory, 2026-08-27): tried seeding
    // 0x3D8768 with the same "3000" constant, reasoning by analogy with the
    // 0x3d8c28 fix above since func_11B8B0 also compares against 0x390F6C.
    // WRONG: a direct diagnostic read at func_11B8B0's own entry point
    // showed 0x3D8768 legitimately holds 0x8 (a real small integer written
    // by some other, not-yet-identified piece of DQ8's own code) by the
    // time the check runs, immediately after our seed -- meaning this is
    // NOT an uninitialized "missing IOP response" slot like 0x3d8c28 is;
    // it's unrelated state, and reusing the same ELF string constant in two
    // places doesn't imply the same semantic purpose. Reverted rather than
    // left in, since it reflected a false premise, not just an unproven one.

    // DIAGNOSTIC: chase the new FUN_00160b00 stall (see project memory,
    // 2026-08-25) -- capture v0 immediately after each synchronous nested
    // call in the FUN_00160b00 -> FUN_0011fa20 -> FUN_0011f7f8 ->
    // FUN_0011f020 chain to find exactly where the negative/failure value
    // first appears, instead of guessing from static disassembly.
    if (targetPc == 0x11fa20u && sourcePc == 0x160accu)
    {
        static std::atomic<uint32_t> s_n1{0u};
        if (s_n1.fetch_add(1u, std::memory_order_relaxed) < 15u)
        {
            std::cerr << "[chase-160acc] FUN_0011fa20 returned v0=0x" << std::hex << getRegU32(ctx, 2) << std::dec << std::endl;
        }
    }
    if (targetPc == 0x11f7f8u && sourcePc == 0x11fa2cu)
    {
        static std::atomic<uint32_t> s_n2{0u};
        if (s_n2.fetch_add(1u, std::memory_order_relaxed) < 15u)
        {
            std::cerr << "[chase-11fa2c] FUN_0011f7f8 returned v0=0x" << std::hex << getRegU32(ctx, 2) << std::dec << std::endl;
        }
    }
    if (targetPc == 0x11f020u && sourcePc == 0x11f828u)
    {
        static std::atomic<uint32_t> s_n3{0u};
        if (s_n3.fetch_add(1u, std::memory_order_relaxed) < 15u)
        {
            std::cerr << "[chase-11f828] FUN_0011f020 cachedBefore=0x" << std::hex << cachedClientAt391040Before
                      << " returned v0=0x" << getRegU32(ctx, 2) << std::dec << std::endl;
        }
    }
    if (targetPc == 0x1325f8u && rdram)
    {
        static std::atomic<uint32_t> s_n4{0u};
        if (s_n4.fetch_add(1u, std::memory_order_relaxed) < 20u)
        {
            std::cerr << "[chase-1325f8-call] source=0x" << std::hex << sourcePc
                      << " a0=0x" << memcmpA0Before << " *a0=0x" << memcmpBuf0Before
                      << " a1=0x" << memcmpA1Before << " *a1=0x" << memcmpBuf1Before
                      << " a2=0x" << memcmpA2Before
                      << " result_v0=0x" << getRegU32(ctx, 2)
                      << std::dec << std::endl;
        }
    }

    if (targetPc == 0x116c20u)
    {
        static std::atomic<uint32_t> s_loggedSifSetReg{0u};
        const uint32_t n = s_loggedSifSetReg.fetch_add(1u, std::memory_order_relaxed);
        if (n < 20u)
        {
            std::cerr << "[sceSifSetReg-call] #" << std::dec << n
                      << " source=0x" << std::hex << sourcePc
                      << " reg=0x" << getRegU32(ctx, 4)
                      << " value=0x" << getRegU32(ctx, 5)
                      << std::dec << std::endl;
        }
    }

    // DIAGNOSTIC: verify the kSifBootReadyMask fix (see project memory,
    // 2026-08-25) actually changed what DQ8 observes from sceSifGetReg(4).
    if (targetPc == 0x116c30u && sourcePc == 0x11ff08u)
    {
        static std::atomic<uint32_t> s_loggedSifGetRegBoot{0u};
        const uint32_t n = s_loggedSifGetRegBoot.fetch_add(1u, std::memory_order_relaxed);
        if (n < 10u)
        {
            std::cerr << "[sifgetreg-boot-check] #" << std::dec << n
                      << " reg=0x" << std::hex << sceSifGetRegArg0
                      << " v0=0x" << getRegU32(ctx, 2)
                      << std::dec << std::endl;
        }
    }

    // DIAGNOSTIC: capture func_11A588's actual return value (v0) the instant
    // its synchronous nested call above returns to FUN_0012ae98's call site
    // (source=0x12af64). This replaces an earlier, flawed "wait for the next
    // dispatch outside func_11A588's range" heuristic that misfired on a
    // fresh re-entry into func_11A588 (via its own internal func_119FA8
    // call) and captured unrelated internal state instead of the true
    // return value. Because DirectCall targets are invoked synchronously
    // right here (this line), v0 immediately after targetFn() returns is
    // unambiguously what the caller (FUN_0012ae98) sees.
    if (targetPc == 0x11a588u && sourcePc == 0x12af64u)
    {
        static std::atomic<uint32_t> s_loggedRealReturn{0u};
        const uint32_t n = s_loggedRealReturn.fetch_add(1u, std::memory_order_relaxed);
        if (n < 20u)
        {
            std::cerr << "[func11a588-real-return] #" << std::dec << n
                      << " v0=0x" << std::hex << getRegU32(ctx, 2)
                      << " pcAfter=0x" << ctx->pc
                      << std::dec << std::endl;
        }
    }

    if (isStopRequested() || ctx->pc == 0u)
    {
        return false;
    }

    if (ctx->pc == entryPc)
    {
        ctx->pc = fallthroughPc;
    }

    return ctx->pc == fallthroughPc;
}

void PS2Runtime::SignalException(R5900Context *ctx, PS2Exception exception)
{
    if (exception == EXCEPTION_INTEGER_OVERFLOW)
    {
        HandleIntegerOverflow(ctx);
        return;
    }

    raiseCop0Exception(ctx, static_cast<uint32_t>(exception),
                       exception == EXCEPTION_TLB_REFILL);
}

void PS2Runtime::executeVU0Microprogram(uint8_t *rdram, R5900Context *ctx, uint32_t address)
{
    (void)rdram;

    uint8_t *const vu0Code = m_memory.getVU0Code();
    uint8_t *const vu0Data = m_memory.getVU0Data();
    const uint32_t startPC = address & ~0x7u;

    if (!vu0Code || !vu0Data || startPC + 8u > PS2_VU0_CODE_SIZE)
    {
        seedVu0IdleSuccess(ctx);
        return;
    }

    m_vu0.reset();
    copyVu0ContextToState(ctx, m_vu0.state());
    m_vu0.execute(vu0Code, PS2_VU0_CODE_SIZE,
                  vu0Data, PS2_VU0_DATA_SIZE,
                  m_gs, &m_memory,
                  startPC, 0u, ctx->vu0_itop, 4096);
    copyVu0StateToContext(m_vu0.state(), ctx);
}

void PS2Runtime::vu0StartMicroProgram(uint8_t *rdram, R5900Context *ctx, uint32_t address)
{
    // VCALLMS and VCALLMSR both route here.
    executeVU0Microprogram(rdram, ctx, address);
}

void PS2Runtime::handleSyscall(uint8_t *rdram, R5900Context *ctx)
{
    handleSyscall(rdram, ctx, 0);
}

void PS2Runtime::handleSyscall(uint8_t *rdram, R5900Context *ctx, uint32_t encodedSyscallId)
{
    if (ctx->in_delay_slot)
    {
        throw std::runtime_error("Attempted to execute a syscall inside a branch delay slot! "
                                 "This breaks the atomic basic block model and is structurally unsupported by the emulator.");
    }

    const uint32_t syscallId = (encodedSyscallId != 0u)
                                   ? encodedSyscallId
                                   : getRegU32(ctx, 3); // $v1 / $3 is the EE kernel syscall number

    {
        static std::atomic<uint32_t> s_syscallLogCount{0u};
        const uint32_t idx = s_syscallLogCount.fetch_add(1u, std::memory_order_relaxed);
        if (idx < 400u)
        {
            std::cerr << "[syscall] #" << std::dec << idx
                      << " id=0x" << std::hex << syscallId
                      << " encoded=0x" << encodedSyscallId
                      << " pc=0x" << ctx->pc
                      << std::dec << std::endl;
        }

        if (syscallId == 0x83u)
        {
            static std::atomic<uint32_t> s_findAddrCallCount{0u};
            static std::atomic<int64_t> s_findAddrLastLogMs{0};
            const uint32_t callIdx = s_findAddrCallCount.fetch_add(1u, std::memory_order_relaxed);
            const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now().time_since_epoch())
                                    .count();
            int64_t last = s_findAddrLastLogMs.load(std::memory_order_relaxed);
            if (callIdx < 5u ||
                (nowMs - last >= 500 &&
                 s_findAddrLastLogMs.compare_exchange_strong(last, nowMs, std::memory_order_relaxed)))
            {
                constexpr uint32_t kMirrorAddr = (0x80011F80u & 0x1FFFFFFFu) + 0x83u * 4u;
                uint32_t mirrorValue = 0xDEADBEEFu;
                if (rdram)
                {
                    std::memcpy(&mirrorValue, rdram + kMirrorAddr, sizeof(mirrorValue));
                }
                std::cerr << "[find-addr-call] call#" << std::dec << callIdx
                          << " a0(start)=0x" << std::hex << getRegU32(ctx, 4)
                          << " a1(end)=0x" << getRegU32(ctx, 5)
                          << " a2(target)=0x" << getRegU32(ctx, 6)
                          << " mirror[0x" << kMirrorAddr << "]=0x" << mirrorValue
                          << std::dec << std::endl;
            }
        }
    }

    if (ps2_syscalls::dispatchNumericSyscall(syscallId, rdram, ctx, this))
    {
        return;
    }

    // God help you
    ps2_syscalls::TODO(rdram, ctx, this, encodedSyscallId);
}

void PS2Runtime::handleBreak(uint8_t *rdram, R5900Context *ctx)
{
    raiseCop0Exception(ctx, EXCEPTION_BREAKPOINT);
}

void PS2Runtime::drainCompletedDmacHandlers(uint8_t *rdram)
{
    for (uint32_t cause : m_memory.consumeCompletedDmacCauses())
    {
        ps2_syscalls::dispatchDmacHandlersForCause(rdram, this, cause);
    }
}

void PS2Runtime::handleTrap(uint8_t *rdram, R5900Context *ctx)
{
    raiseCop0Exception(ctx, EXCEPTION_TRAP);
}

void PS2Runtime::handleTLBR(uint8_t *rdram, R5900Context *ctx)
{
    uint32_t vpn = 0;
    uint32_t pfn = 0;
    uint32_t mask = 0;
    bool valid = false;

    const uint32_t index = ctx->cop0_index & 0x3Fu;
    if (!m_memory.tlbRead(index, vpn, pfn, mask, valid))
    {
        raiseCop0Exception(ctx, EXCEPTION_RESERVED_INSTRUCTION);
        return;
    }

    // Preserve low ASID bits in EntryHi.
    ctx->cop0_entryhi = (ctx->cop0_entryhi & 0x00000FFFu) | (vpn & 0xFFFFF000u);
    ctx->cop0_entrylo0 = (ctx->cop0_entrylo0 & ~0x03FFFFC2u) |
                         ((pfn & 0x000FFFFFu) << 6) |
                         (valid ? 0x2u : 0u);
    ctx->cop0_pagemask = mask & 0x01FFE000u;
}

void PS2Runtime::handleTLBWI(uint8_t *rdram, R5900Context *ctx)
{
    const uint32_t index = ctx->cop0_index & 0x3Fu;
    const uint32_t vpn = ctx->cop0_entryhi & 0xFFFFF000u;
    const uint32_t pfn = (ctx->cop0_entrylo0 >> 6) & 0x000FFFFFu;
    const uint32_t mask = ctx->cop0_pagemask & 0x01FFE000u;
    const bool valid = (ctx->cop0_entrylo0 & 0x2u) != 0u;

    if (!m_memory.tlbWrite(index, vpn, pfn, mask, valid))
    {
        raiseCop0Exception(ctx, EXCEPTION_RESERVED_INSTRUCTION);
    }
}

void PS2Runtime::handleTLBWR(uint8_t *rdram, R5900Context *ctx)
{
    const uint32_t entryCount = static_cast<uint32_t>(m_memory.tlbEntryCount());
    if (entryCount == 0)
    {
        raiseCop0Exception(ctx, EXCEPTION_RESERVED_INSTRUCTION);
        return;
    }

    const uint32_t wired = std::min(ctx->cop0_wired, entryCount - 1);
    uint32_t random = ctx->cop0_random % entryCount;
    if (random < wired)
    {
        random = wired;
    }

    const uint32_t vpn = ctx->cop0_entryhi & 0xFFFFF000u;
    const uint32_t pfn = (ctx->cop0_entrylo0 >> 6) & 0x000FFFFFu;
    const uint32_t mask = ctx->cop0_pagemask & 0x01FFE000u;
    const bool valid = (ctx->cop0_entrylo0 & 0x2u) != 0u;

    if (!m_memory.tlbWrite(random, vpn, pfn, mask, valid))
    {
        raiseCop0Exception(ctx, EXCEPTION_RESERVED_INSTRUCTION);
        return;
    }

    // Keep COP0 bookkeeping in sync with the selected slot.
    ctx->cop0_index = (ctx->cop0_index & ~0x3Fu) | (random & 0x3Fu);
    ctx->cop0_random = (random <= wired) ? (entryCount - 1) : (random - 1);
}

void PS2Runtime::handleTLBP(uint8_t *rdram, R5900Context *ctx)
{
    const int32_t index = m_memory.tlbProbe(ctx->cop0_entryhi & 0xFFFFF000u);
    if (index >= 0)
    {
        ctx->cop0_index = (ctx->cop0_index & ~0x8000003Fu) |
                          (static_cast<uint32_t>(index) & 0x3Fu);
    }
    else
    {
        // MIPS sets probe failure bit (P) in Index[31].
        ctx->cop0_index |= 0x80000000u;
    }
}

void PS2Runtime::clearLLBit(R5900Context *ctx)
{
    // LL/SC reservation is tracked separately from COP0 Status.
    ctx->llbit = 0;
    ctx->lladdr = 0;
}

uint32_t PS2Runtime::alignGuestHeapValue(uint32_t value, uint32_t alignment)
{
    if (alignment == 0)
    {
        return value;
    }

    const uint32_t mask = alignment - 1u;
    if (value > (std::numeric_limits<uint32_t>::max() - mask))
    {
        return std::numeric_limits<uint32_t>::max();
    }
    return (value + mask) & ~mask;
}

bool PS2Runtime::isGuestHeapAlignmentValid(uint32_t alignment)
{
    return alignment != 0u && (alignment & (alignment - 1u)) == 0u;
}

uint32_t PS2Runtime::normalizeGuestHeapAlignment(uint32_t alignment)
{
    if (!isGuestHeapAlignmentValid(alignment))
    {
        return kGuestHeapDefaultAlignment;
    }
    return std::max(alignment, kGuestHeapDefaultAlignment);
}

uint32_t PS2Runtime::clampGuestHeapBase(uint32_t guestBase) const
{
    uint32_t normalized = guestBase;
    if (normalized >= PS2_RAM_SIZE)
    {
        normalized &= PS2_RAM_MASK;
    }
    const uint32_t hardLimit = std::min(kGuestHeapHardLimit, PS2_RAM_SIZE);
    return std::min(normalized, hardLimit);
}

uint32_t PS2Runtime::clampGuestHeapLimit(uint32_t guestLimit) const
{
    const uint32_t hardLimit = std::min(kGuestHeapHardLimit, PS2_RAM_SIZE);
    if (guestLimit == 0u || guestLimit > hardLimit)
    {
        return hardLimit;
    }
    return guestLimit;
}

void PS2Runtime::resetGuestHeapLocked(uint32_t guestBase, uint32_t guestLimit)
{
    uint32_t base = alignGuestHeapValue(clampGuestHeapBase(guestBase), kGuestHeapDefaultAlignment);
    uint32_t limit = clampGuestHeapLimit(guestLimit);
    if (base == 0u)
    {
        const uint32_t fallbackBase = (m_guestHeapSuggestedBase != 0u) ? m_guestHeapSuggestedBase : kGuestHeapDefaultBase;
        base = alignGuestHeapValue(clampGuestHeapBase(fallbackBase), kGuestHeapDefaultAlignment);
    }

    if (limit <= base)
    {
        base = alignGuestHeapValue(clampGuestHeapBase(m_guestHeapSuggestedBase), kGuestHeapDefaultAlignment);
        limit = clampGuestHeapLimit(0u);
    }

    if (limit <= base)
    {
        base = 0u;
        limit = 0u;
    }

    m_guestHeapBlocks.clear();
    if (limit > base)
    {
        m_guestHeapBlocks.push_back({base, limit - base, true});
    }

    m_guestHeapBase = base;
    m_guestHeapEnd = base;
    m_guestHeapLimit = limit;
    m_guestHeapConfigured = true;
}

void PS2Runtime::ensureGuestHeapInitializedLocked()
{
    if (m_guestHeapConfigured)
    {
        return;
    }

    const uint32_t suggested = (m_guestHeapSuggestedBase == 0u) ? kGuestHeapDefaultBase : m_guestHeapSuggestedBase;
    resetGuestHeapLocked(suggested, clampGuestHeapLimit(0u));
}

int32_t PS2Runtime::findGuestHeapBlockIndexLocked(uint32_t guestAddr) const
{
    const uint32_t normalizedAddr = guestAddr & PS2_RAM_MASK;
    for (size_t i = 0; i < m_guestHeapBlocks.size(); ++i)
    {
        const GuestHeapBlock &block = m_guestHeapBlocks[i];
        if (!block.free && block.addr == normalizedAddr)
        {
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

uint32_t PS2Runtime::allocateGuestBlockLocked(uint32_t size, uint32_t alignment)
{
    if (size == 0u)
    {
        return 0u;
    }

    const uint32_t normalizedAlignment = normalizeGuestHeapAlignment(alignment);
    if (size > (std::numeric_limits<uint32_t>::max() - (kGuestHeapDefaultAlignment - 1u)))
    {
        return 0u;
    }

    const uint32_t allocSize = alignGuestHeapValue(size, kGuestHeapDefaultAlignment);
    if (allocSize == 0u)
    {
        return 0u;
    }

    for (size_t i = 0; i < m_guestHeapBlocks.size(); ++i)
    {
        const GuestHeapBlock block = m_guestHeapBlocks[i];
        if (!block.free)
        {
            continue;
        }

        const uint64_t blockStart = block.addr;
        const uint64_t blockEnd = blockStart + static_cast<uint64_t>(block.size);
        const uint32_t alignedAddr = alignGuestHeapValue(block.addr, normalizedAlignment);
        if (alignedAddr < block.addr)
        {
            continue;
        }

        const uint64_t alignedStart = alignedAddr;
        if (alignedStart > blockEnd)
        {
            continue;
        }

        const uint64_t allocEnd = alignedStart + static_cast<uint64_t>(allocSize);
        if (allocEnd > blockEnd)
        {
            continue;
        }

        const uint32_t prefixSize = static_cast<uint32_t>(alignedStart - blockStart);
        const uint32_t suffixSize = static_cast<uint32_t>(blockEnd - allocEnd);

        std::vector<GuestHeapBlock> replacement;
        replacement.reserve(3);
        if (prefixSize > 0u)
        {
            replacement.push_back({block.addr, prefixSize, true});
        }
        replacement.push_back({alignedAddr, allocSize, false});
        if (suffixSize > 0u)
        {
            replacement.push_back({static_cast<uint32_t>(allocEnd), suffixSize, true});
        }

        m_guestHeapBlocks.erase(m_guestHeapBlocks.begin() + static_cast<std::ptrdiff_t>(i));
        m_guestHeapBlocks.insert(m_guestHeapBlocks.begin() + static_cast<std::ptrdiff_t>(i),
                                 replacement.begin(),
                                 replacement.end());

        m_guestHeapEnd = std::max(m_guestHeapEnd, static_cast<uint32_t>(allocEnd));
        return alignedAddr;
    }

    return 0u;
}

void PS2Runtime::coalesceGuestHeapLocked()
{
    if (m_guestHeapBlocks.empty())
    {
        return;
    }

    size_t i = 1;
    while (i < m_guestHeapBlocks.size())
    {
        GuestHeapBlock &prev = m_guestHeapBlocks[i - 1];
        GuestHeapBlock &curr = m_guestHeapBlocks[i];
        const uint64_t prevEnd = static_cast<uint64_t>(prev.addr) + static_cast<uint64_t>(prev.size);
        if (prev.free && curr.free && prevEnd == curr.addr)
        {
            prev.size += curr.size;
            m_guestHeapBlocks.erase(m_guestHeapBlocks.begin() + static_cast<std::ptrdiff_t>(i));
            continue;
        }
        ++i;
    }
}

void PS2Runtime::freeGuestBlockLocked(uint32_t guestAddr)
{
    const int32_t index = findGuestHeapBlockIndexLocked(guestAddr);
    if (index < 0)
    {
        return;
    }

    m_guestHeapBlocks[static_cast<size_t>(index)].free = true;
    coalesceGuestHeapLocked();
}

void PS2Runtime::configureGuestHeap(uint32_t guestBase, uint32_t guestLimit)
{
    std::lock_guard<std::mutex> lock(m_guestHeapMutex);
    uint32_t normalizedBase = alignGuestHeapValue(clampGuestHeapBase(guestBase), kGuestHeapDefaultAlignment);
    if (normalizedBase == 0u)
    {
        normalizedBase = (m_guestHeapSuggestedBase != 0u) ? m_guestHeapSuggestedBase : kGuestHeapDefaultBase;
    }
    m_guestHeapSuggestedBase = normalizedBase;
    resetGuestHeapLocked(normalizedBase, guestLimit);
}

uint32_t PS2Runtime::guestMalloc(uint32_t size, uint32_t alignment)
{
    std::lock_guard<std::mutex> lock(m_guestHeapMutex);
    ensureGuestHeapInitializedLocked();
    return allocateGuestBlockLocked(size, alignment);
}

uint32_t PS2Runtime::guestCalloc(uint32_t count, uint32_t size, uint32_t alignment)
{
    if (count == 0u || size == 0u)
    {
        return 0u;
    }
    if (count > (std::numeric_limits<uint32_t>::max() / size))
    {
        return 0u;
    }

    const uint32_t totalSize = count * size;
    const uint32_t guestAddr = guestMalloc(totalSize, alignment);
    if (guestAddr != 0u)
    {
        uint8_t *rdram = m_memory.getRDRAM();
        if (rdram)
        {
            uint32_t physAddr = guestAddr & PS2_RAM_MASK;
            if (physAddr + totalSize <= PS2_RAM_SIZE)
                std::memset(rdram + physAddr, 0, totalSize);
        }
    }

    return guestAddr;
}

uint32_t PS2Runtime::guestRealloc(uint32_t guestAddr, uint32_t newSize, uint32_t alignment)
{
    if (guestAddr == 0u)
    {
        return guestMalloc(newSize, alignment);
    }
    if (newSize == 0u)
    {
        guestFree(guestAddr);
        return 0u;
    }

    if (newSize > (std::numeric_limits<uint32_t>::max() - (kGuestHeapDefaultAlignment - 1u)))
    {
        return 0u;
    }

    const uint32_t normalizedAlignment = normalizeGuestHeapAlignment(alignment);
    const uint32_t requestedSize = alignGuestHeapValue(newSize, kGuestHeapDefaultAlignment);

    std::lock_guard<std::mutex> lock(m_guestHeapMutex);
    ensureGuestHeapInitializedLocked();

    const int32_t index = findGuestHeapBlockIndexLocked(guestAddr);
    if (index < 0)
    {
        return 0u;
    }

    const size_t blockIndex = static_cast<size_t>(index);
    const uint32_t oldAddr = m_guestHeapBlocks[blockIndex].addr;
    const uint32_t oldSize = m_guestHeapBlocks[blockIndex].size;

    if (requestedSize <= oldSize)
    {
        if (requestedSize < oldSize)
        {
            const uint32_t tailAddr = oldAddr + requestedSize;
            const uint32_t tailSize = oldSize - requestedSize;
            m_guestHeapBlocks[blockIndex].size = requestedSize;
            m_guestHeapBlocks.insert(m_guestHeapBlocks.begin() + static_cast<std::ptrdiff_t>(blockIndex + 1u),
                                     GuestHeapBlock{tailAddr, tailSize, true});
            coalesceGuestHeapLocked();
        }
        return oldAddr;
    }

    if (blockIndex + 1u < m_guestHeapBlocks.size())
    {
        GuestHeapBlock &next = m_guestHeapBlocks[blockIndex + 1u];
        const uint64_t blockEnd = static_cast<uint64_t>(m_guestHeapBlocks[blockIndex].addr) +
                                  static_cast<uint64_t>(m_guestHeapBlocks[blockIndex].size);
        if (next.free && blockEnd == next.addr)
        {
            const uint64_t combined = static_cast<uint64_t>(m_guestHeapBlocks[blockIndex].size) +
                                      static_cast<uint64_t>(next.size);
            if (combined >= requestedSize)
            {
                const uint32_t extraNeeded = requestedSize - m_guestHeapBlocks[blockIndex].size;
                m_guestHeapBlocks[blockIndex].size = requestedSize;
                if (next.size == extraNeeded)
                {
                    m_guestHeapBlocks.erase(m_guestHeapBlocks.begin() + static_cast<std::ptrdiff_t>(blockIndex + 1u));
                }
                else
                {
                    next.addr += extraNeeded;
                    next.size -= extraNeeded;
                }
                m_guestHeapEnd = std::max(m_guestHeapEnd, oldAddr + requestedSize);
                return oldAddr;
            }
        }
    }

    const uint32_t newAddr = allocateGuestBlockLocked(newSize, normalizedAlignment);
    if (newAddr == 0u)
    {
        return 0u;
    }

    uint8_t *rdram = m_memory.getRDRAM();
    if (rdram)
    {
        const uint32_t copyBytes = std::min(oldSize, newSize);
        uint32_t dstPhys = newAddr & PS2_RAM_MASK;
        uint32_t srcPhys = oldAddr & PS2_RAM_MASK;
        if (dstPhys + copyBytes <= PS2_RAM_SIZE && srcPhys + copyBytes <= PS2_RAM_SIZE)
            std::memmove(rdram + dstPhys, rdram + srcPhys, copyBytes);
    }

    freeGuestBlockLocked(oldAddr);
    return newAddr;
}

void PS2Runtime::guestFree(uint32_t guestAddr)
{
    if (guestAddr == 0u)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(m_guestHeapMutex);
    ensureGuestHeapInitializedLocked();
    freeGuestBlockLocked(guestAddr);
}

uint32_t PS2Runtime::guestHeapBase() const
{
    std::lock_guard<std::mutex> lock(m_guestHeapMutex);
    return m_guestHeapConfigured ? m_guestHeapBase : m_guestHeapSuggestedBase;
}

uint32_t PS2Runtime::guestHeapEnd() const
{
    std::lock_guard<std::mutex> lock(m_guestHeapMutex);
    return m_guestHeapConfigured ? m_guestHeapEnd : m_guestHeapSuggestedBase;
}

uint32_t PS2Runtime::guestHeapLimit() const
{
    std::lock_guard<std::mutex> lock(m_guestHeapMutex);
    return m_guestHeapConfigured ? m_guestHeapLimit : m_guestHeapSuggestedBase;
}

uint32_t PS2Runtime::reserveAsyncCallbackStack(uint32_t size, uint32_t alignment)
{
    if (size == 0u)
    {
        return 0u;
    }

    const uint32_t normalizedAlignment = normalizeGuestHeapAlignment(alignment);
    const uint32_t allocSize = alignGuestHeapValue(size, kGuestHeapDefaultAlignment);
    if (allocSize == 0u)
    {
        return 0u;
    }

    std::lock_guard<std::mutex> lock(m_asyncCallbackStackMutex);
    uint32_t top = m_asyncCallbackStackTop;
    if (top > PS2_RAM_SIZE)
    {
        top = PS2_RAM_SIZE;
    }
    top &= ~(kGuestHeapDefaultAlignment - 1u);

    if (top <= allocSize)
    {
        return 0u;
    }

    uint32_t base = top - allocSize;
    base &= ~(normalizedAlignment - 1u);
    if (base < m_asyncCallbackStackFloor || base >= top)
    {
        return 0u;
    }

    m_asyncCallbackStackTop = base;
    return top - 0x10u;
}

uint8_t PS2Runtime::Load8(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr)
{
    try
    {
        return m_memory.read8(vaddr);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_LOAD);
        return 0;
    }
}

uint16_t PS2Runtime::Load16(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr)
{
    try
    {
        return m_memory.read16(vaddr);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_LOAD);
        return 0;
    }
}

uint32_t PS2Runtime::Load32(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr)
{
    try
    {
        return m_memory.read32(vaddr);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_LOAD);
        return 0;
    }
}

uint64_t PS2Runtime::Load64(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr)
{
    try
    {
        return m_memory.read64(vaddr);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_LOAD);
        return 0;
    }
}

__m128i PS2Runtime::Load128(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr)
{
    try
    {
        return m_memory.read128(vaddr);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_LOAD);
        return _mm_setzero_si128();
    }
}

void PS2Runtime::Store8(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, uint8_t value)
{
    ps2TraceGuestWrite(rdram, vaddr, 1u, value, 0u, "WRITE8", ctx);
    try
    {
        m_memory.write8(vaddr, value);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_STORE);
    }
}

void PS2Runtime::Store16(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, uint16_t value)
{
    ps2TraceGuestWrite(rdram, vaddr, 2u, value, 0u, "WRITE16", ctx);
    try
    {
        m_memory.write16(vaddr, value);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_STORE);
    }
}

void PS2Runtime::Store32(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, uint32_t value)
{
    ps2TraceGuestWrite(rdram, vaddr, 4u, value, 0u, "WRITE32", ctx);
    try
    {
        m_memory.write32(vaddr, value);
        drainCompletedDmacHandlers(rdram);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_STORE);
    }
}

void PS2Runtime::Store64(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, uint64_t value)
{
    ps2TraceGuestWrite(rdram, vaddr, 8u, value, 0u, "WRITE64", ctx);
    try
    {
        m_memory.write64(vaddr, value);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_STORE);
    }
}

void PS2Runtime::Store128(uint8_t *rdram, R5900Context *ctx, uint32_t vaddr, __m128i value)
{
    alignas(16) uint64_t _parts[2];
    _mm_storeu_si128(reinterpret_cast<__m128i *>(_parts), value);
    ps2TraceGuestWrite(rdram, vaddr, 16u, _parts[0], _parts[1], "WRITE128", ctx);
    try
    {
        m_memory.write128(vaddr, value);
    }
    catch (const std::exception &)
    {
        SignalException(ctx, EXCEPTION_ADDRESS_ERROR_STORE);
    }
}

void PS2Runtime::kickGifDmaChainFromMMIO(uint8_t *rdram,
                                         R5900Context *ctx,
                                         uint32_t dPcrValue,
                                         uint32_t dStatValue,
                                         uint32_t tadr,
                                         uint32_t chcr)
{
    constexpr uint32_t D_PCR = 0x1000E020u;
    constexpr uint32_t D_STAT = 0x1000E010u;
    constexpr uint32_t GIF_TADR = 0x1000A030u;
    constexpr uint32_t GIF_CHCR = 0x1000A000u;

    ps2TraceGuestWrite(rdram, D_PCR, 4u, dPcrValue, 0u, "WRITE32", ctx);
    m_memory.writeIORegister(D_PCR, dPcrValue);
    ps2TraceGuestWrite(rdram, D_STAT, 4u, dStatValue, 0u, "WRITE32", ctx);
    m_memory.writeIORegister(D_STAT, dStatValue);
    ps2TraceGuestWrite(rdram, GIF_TADR, 4u, tadr, 0u, "WRITE32", ctx);
    m_memory.writeIORegister(GIF_TADR, tadr);
    ps2TraceGuestWrite(rdram, GIF_CHCR, 4u, chcr, 0u, "WRITE32", ctx);
    if (m_memory.tryProcessNativeGifImageUploadChain(m_gs, tadr, chcr))
    {
        drainCompletedDmacHandlers(rdram);
        return;
    }
    if (m_memory.tryProcessNativeGifPackedChain(m_gs, tadr, chcr))
    {
        drainCompletedDmacHandlers(rdram);
        return;
    }
    m_memory.writeIORegister(GIF_CHCR, chcr);
    m_memory.processPendingTransfers();
    drainCompletedDmacHandlers(rdram);
}

void PS2Runtime::requestStop()
{
    m_stopRequested.store(true, std::memory_order_relaxed);
    if (m_eeScheduler)
    {
        m_eeScheduler->requestStop();
    }
}

bool PS2Runtime::isStopRequested() const
{
    return m_stopRequested.load(std::memory_order_relaxed);
}

EeScheduler &PS2Runtime::eeScheduler()
{
    return *m_eeScheduler;
}

const EeScheduler &PS2Runtime::eeScheduler() const
{
    return *m_eeScheduler;
}

Ps2DiscFs *PS2Runtime::discFs()
{
    if (!m_discFsOpenAttempted)
    {
        m_discFsOpenAttempted = true;
        // Hardcoded path, matching this session's established pattern of
        // hardcoded constants where no config system exists yet (see
        // project memory 2026-08-27). Validated standalone against this
        // exact ISO before integration: SLUS_212.07 read back byte-for-byte
        // identical to the known-good extracted copy, SYSTEM.CNF read
        // correctly, and MODULES/CDVDSTM.IRX located via directory
        // traversal with the exact expected size.
        constexpr const char *kDq8IsoPath =
            "C:\\Users\\liorv\\Downloads\\Dragon Quest VIII - Journey of the Cursed King (USA)\\Dragon Quest VIII - Journey of the Cursed King (USA).iso";
        m_discFs = Ps2DiscFs::Open(kDq8IsoPath);
        if (m_discFs)
        {
            uint32_t lba = 0, size = 0;
            const bool located = m_discFs->Locate("SLUS_212.07", lba, size);
            std::cerr << "[disc-fs] opened DQ8 ISO successfully; SLUS_212.07 located="
                      << located << " lba=" << lba << " size=" << size << std::endl;
        }
        else
        {
            std::cerr << "[disc-fs] FAILED to open DQ8 ISO at " << kDq8IsoPath << std::endl;
        }
    }
    return m_discFs.get();
}

void PS2Runtime::postEeEvent(EeEvent event)
{
    m_eeScheduler->postEvent(event);
}

bool PS2Runtime::eeCheckpointDue(uint32_t cycles) noexcept
{
    const bool due = m_eeScheduler->checkpointDue(cycles);
    if (due)
    {
        static std::atomic<uint32_t> s_loggedEeCheckpointDue{0u};
        if (s_loggedEeCheckpointDue.fetch_add(1u, std::memory_order_relaxed) < 30u)
        {
            std::cerr << "[eeCheckpointDue-true] pc=0x" << std::hex
                      << (m_eeScheduler->currentContext() ? m_eeScheduler->currentContext()->pc : 0u)
                      << std::dec << " threadId=" << m_eeScheduler->currentThreadId()
                      << std::endl;
        }
    }
    return due;
}

[[noreturn]] void PS2Runtime::eeWaitVSyncTicks(uint32_t ticks, uint32_t resumePc)
{
    const uint64_t currentTick = m_eeScheduler->currentVSyncTick();
    const uint64_t waitTicks = std::max<uint64_t>(1u, ticks);
    m_eeScheduler->waitVSync(currentTick + waitTicks - 1u,
                             0,
                             [resumePc](R5900Context &context)
                             {
                                 context.pc = resumePc;
                             });
}

void PS2Runtime::addEeExitHandler(int threadId, uint32_t function, uint32_t argument)
{
    std::lock_guard lock(m_eeKernelStateMutex);
    m_eeExitHandlers[threadId].push_back({function, argument});
}

std::vector<PS2Runtime::EeExitHandlerRegistration> PS2Runtime::takeEeExitHandlers(int threadId)
{
    std::lock_guard lock(m_eeKernelStateMutex);
    auto it = m_eeExitHandlers.find(threadId);
    if (it == m_eeExitHandlers.end())
    {
        return {};
    }
    auto handlers = std::move(it->second);
    m_eeExitHandlers.erase(it);
    return handlers;
}

void PS2Runtime::removeEeExitHandlers(int threadId)
{
    std::lock_guard lock(m_eeKernelStateMutex);
    m_eeExitHandlers.erase(threadId);
}

bool PS2Runtime::findEeSyscallOverride(uint32_t syscallNumber, uint32_t &handler) const
{
    std::lock_guard lock(m_eeKernelStateMutex);
    const auto it = m_eeSyscallOverrides.find(syscallNumber);
    if (it == m_eeSyscallOverrides.end())
    {
        return false;
    }
    handler = it->second;
    return true;
}

void PS2Runtime::setEeSyscallOverride(uint8_t *rdram, uint32_t syscallNumber, uint32_t handler)
{
    constexpr uint32_t kTableBase = 0x80011F80u & 0x1FFFFFFFu;
    constexpr uint32_t kMirrorLimit = 0x00080000u;
    const int64_t offset = static_cast<int64_t>(static_cast<int32_t>(syscallNumber)) * 4;
    const int64_t address = static_cast<int64_t>(kTableBase) + offset;

    std::lock_guard lock(m_eeKernelStateMutex);
    if (handler == 0u)
    {
        m_eeSyscallOverrides.erase(syscallNumber);
    }
    else
    {
        m_eeSyscallOverrides[syscallNumber] = handler;
    }
    if (!rdram || address < 0 || address + 4 > kMirrorLimit)
    {
        return;
    }
    const uint32_t guestAddress = static_cast<uint32_t>(address);
    std::memcpy(rdram + guestAddress, &handler, sizeof(handler));
    if (handler == 0u)
    {
        m_eeSyscallMirrorAddresses.erase(guestAddress);
    }
    else
    {
        m_eeSyscallMirrorAddresses.insert(guestAddress);
    }
}

void PS2Runtime::initializeEeKernelState(uint8_t *rdram)
{
    if (!rdram)
    {
        return;
    }
    constexpr uint32_t kTableGuestBase = 0x80011F80u;
    constexpr uint32_t kTableBase = kTableGuestBase & 0x1FFFFFFFu;
    constexpr uint32_t kMirrorLimit = 0x00080000u;
    constexpr uint32_t kProbeBase = 0x000002F0u;

    std::lock_guard lock(m_eeKernelStateMutex);
    for (const uint32_t address : m_eeSyscallMirrorAddresses)
    {
        const uint32_t zero = 0u;
        std::memcpy(rdram + address, &zero, sizeof(zero));
    }
    m_eeSyscallMirrorAddresses.clear();
    const uint32_t high = kTableGuestBase >> 16;
    const uint32_t low = kTableGuestBase & 0xFFFFu;
    std::memcpy(rdram + kProbeBase, &high, sizeof(high));
    std::memcpy(rdram + kProbeBase + 8u, &low, sizeof(low));
    m_eeSyscallMirrorAddresses.insert(kProbeBase);
    m_eeSyscallMirrorAddresses.insert(kProbeBase + 8u);

    for (const auto &[syscallNumber, handler] : m_eeSyscallOverrides)
    {
        const int64_t offset = static_cast<int64_t>(static_cast<int32_t>(syscallNumber)) * 4;
        const int64_t address = static_cast<int64_t>(kTableBase) + offset;
        if (address < 0 || address + 4 > kMirrorLimit)
        {
            continue;
        }
        const uint32_t guestAddress = static_cast<uint32_t>(address);
        std::memcpy(rdram + guestAddress, &handler, sizeof(handler));
        m_eeSyscallMirrorAddresses.insert(guestAddress);
    }
}

void PS2Runtime::HandleIntegerOverflow(R5900Context *ctx)
{
    raiseCop0Exception(ctx, EXCEPTION_INTEGER_OVERFLOW);
}

void PS2Runtime::run()
{
    m_stopRequested.store(false, std::memory_order_relaxed);
    ps2_stubs::resetSifState();
    resetIop();
    ps2_stubs::resetAudioStubState();
    ps2_stubs::resetMpegStubState();
    initializeEeKernelState(m_memory.getRDRAM());
    m_cpuContext.r[4] = _mm_setzero_si128();
    m_cpuContext.r[5] = _mm_setzero_si128();
    m_cpuContext.r[29] = _mm_set_epi64x(0, static_cast<int64_t>(PS2_RAM_SIZE - 0x10u));
    m_debugPc.store(m_cpuContext.pc, std::memory_order_relaxed);
    m_debugRa.store(static_cast<uint32_t>(_mm_extract_epi32(m_cpuContext.r[31], 0)), std::memory_order_relaxed);
    m_debugSp.store(static_cast<uint32_t>(_mm_extract_epi32(m_cpuContext.r[29], 0)), std::memory_order_relaxed);
    m_debugGp.store(static_cast<uint32_t>(_mm_extract_epi32(m_cpuContext.r[28], 0)), std::memory_order_relaxed);

    RUNTIME_LOG("Starting execution at address 0x" << std::hex << m_cpuContext.pc << std::dec);

    // A blank image to use as a framebuffer
    Image blank = GenImageColor(FB_WIDTH, FB_HEIGHT, BLANK);
    Texture2D frameTex = LoadTextureFromImage(blank);
    UnloadImage(blank);

    std::atomic<bool> gameThreadFinished{false};

    std::thread gameThread([&]()
                           {
        ThreadNaming::SetCurrentThreadName("GameThread");
        try
        {
            m_eeScheduler->reset(m_memory.getRDRAM(), m_cpuContext);
            m_eeScheduler->run();
            uint32_t pc = m_debugPc.load(std::memory_order_relaxed);
            RUNTIME_LOG("Game thread returned. PC=0x" << std::hex << pc
                      << " RA=0x" << static_cast<uint32_t>(_mm_extract_epi32(m_cpuContext.r[31], 0)) << std::dec << std::endl);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error during program execution: " << e.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Error during program execution: unknown exception" << std::endl;
        }
        gameThreadFinished.store(true, std::memory_order_release); });

    uint64_t tick = 0;
    while (!isStopRequested() && !gameThreadFinished.load(std::memory_order_acquire))
    {
        PS2_IF_AGRESSIVE_LOGS({
            tick++;
            if ((tick % 120) == 0)
            {
                uint64_t curDma = m_memory.dmaStartCount();
                uint64_t curGif = m_memory.gifCopyCount();
                uint64_t curGs = m_memory.gsWriteCount();
                uint64_t curVif = m_memory.vifWriteCount();
                const GSRegisters &gs = m_memory.gs();
                const uint32_t dbgPc = m_debugPc.load(std::memory_order_relaxed);
                const uint32_t dbgRa = m_debugRa.load(std::memory_order_relaxed);
                const uint32_t dbgSp = m_debugSp.load(std::memory_order_relaxed);
                const uint32_t dbgGp = m_debugGp.load(std::memory_order_relaxed);
                const auto eeSnapshot = m_eeScheduler->snapshot();

                RUNTIME_LOG("[run:tick] tick=" << tick
                                               << " pc=0x" << std::hex << dbgPc
                                               << " ra=0x" << dbgRa
                                               << " sp=0x" << dbgSp
                                               << " gp=0x" << dbgGp
                                               << " dispfb1=0x" << gs.dispfb1
                                               << " display1=0x" << gs.display1
                                               << std::dec
                                               << " activeThreads=" << eeSnapshot.threads.size()
                                               << " dma=" << curDma
                                               << " gif=" << curGif
                                               << " gsw=" << curGs
                                               << " vif=" << curVif
                                               << std::endl);
            }
        });
        uint32_t presentWidth = FB_WIDTH;
        uint32_t presentHeight = DEFAULT_DISPLAY_HEIGHT;
        UploadFrame(frameTex, this, presentWidth, presentHeight);

        BeginDrawing();
        ClearBackground(BLACK);
        const float srcWidth = static_cast<float>(std::max<uint32_t>(1u, presentWidth));
        const float srcHeight = static_cast<float>(std::max<uint32_t>(1u, presentHeight));
        const float screenWidth = static_cast<float>(GetScreenWidth());
        const float screenHeight = static_cast<float>(GetScreenHeight());
        const float scale = std::min(screenWidth / srcWidth, screenHeight / srcHeight);
        const float dstWidth = srcWidth * scale;
        const float dstHeight = srcHeight * scale;
        const Rectangle srcRect{0.0f, 0.0f, srcWidth, srcHeight};
        const Rectangle dstRect{
            (screenWidth - dstWidth) * 0.5f,
            (screenHeight - dstHeight) * 0.5f,
            dstWidth,
            dstHeight};
        DrawTexturePro(frameTex, srcRect, dstRect, Vector2{0.0f, 0.0f}, 0.0f, WHITE);
        if (m_debugUiInitialized && m_debugUiDrawCallback)
        {
            m_debugUiDrawCallback(*this, m_debugUiUserData);
        }
        EndDrawing();

        // DIAGNOSTIC (see project memory, 2026-08-25): periodically dump a
        // screenshot to see what DQ8 is actually rendering at this point in
        // boot -- visual ground truth for whether it has reached a genuine
        // idle/title-screen state versus a blank/broken one.
        {
            static std::atomic<int64_t> s_lastScreenshotMs{0};
            const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count();
            int64_t last = s_lastScreenshotMs.load(std::memory_order_relaxed);
            if (nowMs - last >= 5000 &&
                s_lastScreenshotMs.compare_exchange_strong(last, nowMs, std::memory_order_relaxed))
            {
                TakeScreenshot("dq8_r5900/screenshot_latest.png");
            }
        }

        if (WindowShouldClose())
        {
            RUNTIME_LOG("[run] window close requested, breaking out of loop");
            requestStop();
            break;
        }
    }

    requestStop();
    if (gameThread.joinable())
    {
        gameThread.join();
    }

    if (m_debugUiInitialized && m_debugUiShutdownCallback)
    {
        m_debugUiShutdownCallback(*this, m_debugUiUserData);
        m_debugUiInitialized = false;
    }
    UnloadTexture(frameTex);
    CloseWindow();

    RUNTIME_LOG("[run] exiting loop");
}
