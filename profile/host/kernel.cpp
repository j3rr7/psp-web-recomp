#include "kernel.hpp"

#include "cheats.hpp"

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>

namespace pspweb {
namespace {

#ifdef __EMSCRIPTEN__
// std::chrono goes through clock_gettime and a BigInt conversion in the
// browser; performance.now() directly is several times cheaper.
struct Clock {
    using duration = std::chrono::nanoseconds;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::time_point<Clock>;
    static constexpr bool is_steady = true;
    static time_point now() { return time_point(duration(static_cast<rep>(emscripten_get_now() * 1e6))); }
};
#else
using Clock = std::chrono::steady_clock;
#endif

constexpr std::uint64_t kFrameUs = 16683u; // 59.94 Hz
constexpr std::uint32_t kHeartbeatInterval = 1024u;

constexpr std::uint32_t kErrorNoMemory = 0x80020190u;
constexpr std::uint32_t kErrorUnknownUid = 0x800200CBu;
constexpr std::uint32_t kErrorUnknownThread = 0x80020198u;
constexpr std::uint32_t kErrorUnknownSema = 0x80020199u;
constexpr std::uint32_t kErrorUnknownEventFlag = 0x8002019Au;
constexpr std::uint32_t kErrorNotDormant = 0x800201A4u;
constexpr std::uint32_t kErrorWaitTimeout = 0x800201A8u;
constexpr std::uint32_t kErrorSemaZero = 0x800201ADu;
constexpr std::uint32_t kErrorSemaOverflow = 0x800201AEu;
constexpr std::uint32_t kErrorEventFlagCondition = 0x800201AFu;
constexpr std::uint32_t kErrorWaitDelete = 0x800201B5u;
constexpr std::uint32_t kErrorIllegalCount = 0x800201BDu;
constexpr std::uint32_t kErrorUnknownMbx = 0x8002019Bu;
constexpr std::uint32_t kErrorUnknownAlarm = 0x8002019Fu;
constexpr std::uint32_t kErrorMbxNoMessage = 0x800201B2u;
constexpr std::uint32_t kErrorUnknownMutex = 0x800201C3u;
constexpr std::uint32_t kErrorMutexLocked = 0x800201C4u;
constexpr std::uint32_t kErrorMutexUnlockUnderflow = 0x800201C7u;
constexpr std::uint32_t kErrorMutexRecursive = 0x800201C8u;
constexpr std::uint32_t kVblankInterrupt = 30u;

constexpr std::uint32_t kEventWaitOr = 0x01u;
constexpr std::uint32_t kEventWaitClearAll = 0x10u;
constexpr std::uint32_t kEventWaitClear = 0x20u;

Kernel *g_kernel = nullptr;
psprecomp::Runtime *g_runtime = nullptr;
Clock::time_point g_slice_deadline{};

void slice_heartbeat(std::uint64_t, std::uint32_t) {
    if (Clock::now() >= g_slice_deadline) g_runtime->stop("slice");
    else if (g_kernel->interrupt_pending()) g_runtime->stop("interrupt");
}

void thread_return_trampoline(psprecomp::Runtime &, psprecomp::AllegrexContext &ctx) {
    g_kernel->thread_returned(ctx);
}

std::string hex(std::uint32_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << value;
    return out.str();
}

std::uint32_t align_up(std::uint32_t value, std::uint32_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

std::int64_t real_now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
}

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

// PSP paths are case-insensitive; the extracted disc keeps its original case.
std::filesystem::path resolve_case(const std::filesystem::path &root, const std::string &relative) {
    std::filesystem::path current = root;
    std::stringstream parts(relative);
    std::string part;
    while (std::getline(parts, part, '/')) {
        if (part.empty() || part == ".") continue;
        std::filesystem::path exact = current / part;
        std::error_code ec;
        if (std::filesystem::exists(exact, ec)) {
            current = exact;
            continue;
        }
        bool found = false;
        if (std::filesystem::is_directory(current, ec)) {
            const std::string wanted = lower(part);
            for (const auto &entry : std::filesystem::directory_iterator(current, ec)) {
                if (lower(entry.path().filename().string()) == wanted) {
                    current = entry.path();
                    found = true;
                    break;
                }
            }
        }
        if (!found) current = exact;
    }
    return current;
}

} // namespace

Kernel::Kernel(psprecomp::Runtime &runtime)
    : rt_(runtime), ge_(std::make_unique<Ge>(runtime.memory())), ge_worker_(std::make_unique<GeWorker>(*ge_)) {
    g_kernel = this;
    g_runtime = &runtime;
    frame_real_start_ns_ = real_now_ns();
    reserve(kUserPartitionStart, 0x4000u, "loader");
    ge_->set_signal_sink([this](std::int32_t callback, bool finish, std::uint32_t value) {
        const std::lock_guard<std::mutex> lock(ge_events_mutex_);
        ge_events_.push_back(GeEvent{callback, finish, value});
        ge_event_pending_.store(true, std::memory_order_relaxed);
    });
}

void Kernel::set_roots(std::filesystem::path disc_root, std::filesystem::path memstick_root) {
    disc_root_ = std::move(disc_root);
    memstick_root_ = std::move(memstick_root);
}

std::uint64_t Kernel::now_us() const {
    const std::int64_t elapsed_ns = real_now_ns() - frame_real_start_ns_;
    std::uint64_t elapsed_us = elapsed_ns > 0 ? static_cast<std::uint64_t>(elapsed_ns / 1000) : 0u;
    // A frame is one vblank long however long the host took to run it.  The
    // frame start is the anchor; real time only fills in *how far into* that
    // frame we are, so it must not carry us past the frame's end.  Without this
    // clamp a frame that overruns its budget -- the idle warp loop below still
    // running when the deadline hits, a slow machine, a backgrounded tab --
    // hands the guest frame_start + real_elapsed, which is more than one frame
    // of time.  The game then sees every timer and every movement integration
    // run fast, and by an amount that varies per frame, so the clock jumps.
    if (elapsed_us > kFrameUs) elapsed_us = kFrameUs;
    return frame_start_guest_us_ + elapsed_us + warp_us_;
}

void Kernel::finish(Ctx &ctx, std::uint32_t result) {
    ctx.gpr[2] = result;
    ctx.pc = ctx.gpr[31];
}

void Kernel::finish64(Ctx &ctx, std::uint64_t result) {
    ctx.gpr[2] = static_cast<std::uint32_t>(result);
    ctx.gpr[3] = static_cast<std::uint32_t>(result >> 32u);
    ctx.pc = ctx.gpr[31];
}

std::string Kernel::read_string(std::uint32_t address, std::size_t limit) const {
    std::string text;
    if (address == 0u) return text;
    for (std::size_t i = 0; i < limit; ++i) {
        const char c = static_cast<char>(rt_.memory().load8(address + static_cast<std::uint32_t>(i)));
        if (c == '\0') break;
        text.push_back(c);
    }
    return text;
}

std::filesystem::path Kernel::host_path(const std::string &psp_path) const {
    std::string path = psp_path;
    const auto colon = path.find(':');
    if (colon == std::string::npos) {
        std::string base = cwd_;
        if (!base.empty() && base.back() != '/') base.push_back('/');
        path = base + path;
    }
    const auto device_end = path.find(':');
    const std::string device = lower(path.substr(0, device_end));
    std::string rest = path.substr(device_end + 1u);
    const std::filesystem::path &root =
        (device.rfind("ms", 0) == 0 || device.rfind("fatms", 0) == 0) ? memstick_root_ : disc_root_;
    return resolve_case(root, rest);
}

// ---------------------------------------------------------------------------
// Registration

void Kernel::hle(const char *library, std::uint32_t nid, const char *name,
                 void (Kernel::*handler)(Ctx &)) {
    static const bool trace = std::getenv("PSPWEB_TRACE_HLE") != nullptr;
    if (trace) {
        rt_.register_hle(library, nid, [this, handler, name](psprecomp::Runtime &, Ctx &ctx) {
            const std::int32_t caller = current_uid_;
            std::cerr << "[hle] " << caller << " " << name << "(" << hex(ctx.gpr[4]) << ", " << hex(ctx.gpr[5]) << ", "
                      << hex(ctx.gpr[6]) << ", " << hex(ctx.gpr[7]) << ", " << hex(ctx.gpr[8]) << ")";
            ++hle_calls_;
            (this->*handler)(ctx);
            std::cerr << (current_uid_ == caller ? " -> " + hex(ctx.gpr[2]) : std::string(" -> (switched)")) << "\n";
        });
    } else {
        rt_.register_hle(library, nid, [this, handler, name](psprecomp::Runtime &, Ctx &ctx) {
            ++hle_calls_;
            // Cheap always-on breadcrumb: the watchdog dump uses it to name the
            // HLE call each thread is sitting in when the guest stalls.
            last_hle_[current_uid_] = name;
            (this->*handler)(ctx);
        });
    }
    rt_.nids().add(library, nid, name);
    registered_.insert(std::string(library) + ":" + hex(nid));
}

void Kernel::install_fallback(const psprecomp::PspImport &import) {
    const std::string key = import.library + ":" + hex(import.nid);
    if (registered_.contains(key)) return;
    registered_.insert(key);
    const std::string name = import.library + "::" +
        rt_.nids().resolve(import.library, import.nid).value_or(hex(import.nid));
    rt_.register_hle(import.library, import.nid, [this, name](psprecomp::Runtime &, Ctx &ctx) {
        if (fallback_logged_.insert(name).second) {
            std::cerr << "[hle] unimplemented " << name << "(" << hex(ctx.gpr[4]) << ", " << hex(ctx.gpr[5])
                      << ", " << hex(ctx.gpr[6]) << ", " << hex(ctx.gpr[7]) << ") -> 0\n";
        }
        finish(ctx, 0u);
    });
}

void Kernel::install(const std::vector<psprecomp::PspImport> &imports) {
    rt_.register_function(kThreadReturnAddress, &thread_return_trampoline, "pspweb_thread_return");
    psprecomp::set_runtime_heartbeat_hook(&slice_heartbeat, kHeartbeatInterval);

    const char *tm = "ThreadManForUser";
    hle(tm, 0x446D8DE6u, "sceKernelCreateThread", &Kernel::sceKernelCreateThread);
    hle(tm, 0xF475845Du, "sceKernelStartThread", &Kernel::sceKernelStartThread);
    hle(tm, 0xAA73C935u, "sceKernelExitThread", &Kernel::sceKernelExitThread);
    hle(tm, 0x809CE29Bu, "sceKernelExitDeleteThread", &Kernel::sceKernelExitDeleteThread);
    hle(tm, 0x9FA03CD3u, "sceKernelDeleteThread", &Kernel::sceKernelDeleteThread);
    hle(tm, 0x383F7BCCu, "sceKernelTerminateDeleteThread", &Kernel::sceKernelTerminateDeleteThread);
    hle(tm, 0x616403BAu, "sceKernelTerminateThread", &Kernel::sceKernelTerminateDeleteThread);
    hle(tm, 0x9ACE131Eu, "sceKernelSleepThread", &Kernel::sceKernelSleepThread);
    hle(tm, 0x82826F70u, "sceKernelSleepThreadCB", &Kernel::sceKernelSleepThread);
    hle(tm, 0xD59EAD2Fu, "sceKernelWakeupThread", &Kernel::sceKernelWakeupThread);
    hle(tm, 0xCEADEB47u, "sceKernelDelayThread", &Kernel::sceKernelDelayThread);
    hle(tm, 0x68DA9E36u, "sceKernelDelayThreadCB", &Kernel::sceKernelDelayThread);
    hle(tm, 0x293B45B8u, "sceKernelGetThreadId", &Kernel::sceKernelGetThreadId);
    hle(tm, 0x94AA61EEu, "sceKernelGetThreadCurrentPriority", &Kernel::sceKernelGetThreadCurrentPriority);
    hle(tm, 0x71BC9871u, "sceKernelChangeThreadPriority", &Kernel::sceKernelChangeThreadPriority);
    hle(tm, 0x278C0DF5u, "sceKernelWaitThreadEnd", &Kernel::sceKernelWaitThreadEnd);
    hle(tm, 0x840E8133u, "sceKernelWaitThreadEndCB", &Kernel::sceKernelWaitThreadEnd);
    hle(tm, 0xE81CAF8Fu, "sceKernelCreateCallback", &Kernel::sceKernelCreateCallback);
    hle(tm, 0x0C3B4778u, "sceKernelRegisterCallback", &Kernel::sceKernelRegisterCallback);
    hle(tm, 0x349D6D6Cu, "sceKernelCheckCallback", &Kernel::sceKernelCheckCallback);
    hle(tm, 0x369ED59Du, "sceKernelGetSystemTimeLow", &Kernel::sceKernelGetSystemTimeLow);
    hle(tm, 0x82BC5777u, "sceKernelGetSystemTimeWide", &Kernel::sceKernelGetSystemTimeWide);
    hle(tm, 0xDB738F35u, "sceKernelGetSystemTime", &Kernel::sceKernelGetSystemTime);
    hle(tm, 0x110DEC9Au, "sceKernelUSec2SysClock", &Kernel::sceKernelUSec2SysClock);
    hle(tm, 0xC8CD158Cu, "sceKernelUSec2SysClockWide", &Kernel::sceKernelUSec2SysClockWide);
    hle(tm, 0xBA6B92E2u, "sceKernelSysClock2USec", &Kernel::sceKernelSysClock2USec);
    hle(tm, 0xE1619D7Cu, "sceKernelSysClock2USecWide", &Kernel::sceKernelSysClock2USecWide);
    hle(tm, 0xD6DA4BA1u, "sceKernelCreateSema", &Kernel::sceKernelCreateSema);
    hle(tm, 0xB7D098C6u, "sceKernelCreateMutex", &Kernel::sceKernelCreateMutex);
    hle(tm, 0xF8170FBEu, "sceKernelDeleteMutex", &Kernel::sceKernelDeleteMutex);
    hle(tm, 0xB011B11Fu, "sceKernelLockMutex", &Kernel::sceKernelLockMutex);
    hle(tm, 0x5BF4DD27u, "sceKernelLockMutexCB", &Kernel::sceKernelLockMutex);
    hle(tm, 0x0DDCD2C9u, "sceKernelTryLockMutex", &Kernel::sceKernelTryLockMutex);
    hle(tm, 0x6B30100Fu, "sceKernelUnlockMutex", &Kernel::sceKernelUnlockMutex);
    hle(tm, 0x8125221Du, "sceKernelCreateMbx", &Kernel::sceKernelCreateMbx);
    hle(tm, 0x86255ADAu, "sceKernelDeleteMbx", &Kernel::sceKernelDeleteMbx);
    hle(tm, 0xE9B3061Eu, "sceKernelSendMbx", &Kernel::sceKernelSendMbx);
    hle(tm, 0x18260574u, "sceKernelReceiveMbx", &Kernel::sceKernelReceiveMbx);
    hle(tm, 0xF3986382u, "sceKernelReceiveMbxCB", &Kernel::sceKernelReceiveMbx);
    hle(tm, 0x0D81716Au, "sceKernelPollMbx", &Kernel::sceKernelPollMbx);
    hle(tm, 0xEA748E31u, "sceKernelChangeCurrentThreadAttr", &Kernel::return_zero);
    const char *im = "InterruptManager";
    hle(im, 0xCA04A2B9u, "sceKernelRegisterSubIntrHandler", &Kernel::sceKernelRegisterSubIntrHandler);
    hle(im, 0xD61E6961u, "sceKernelReleaseSubIntrHandler", &Kernel::sceKernelReleaseSubIntrHandler);
    hle(im, 0xFB8E22ECu, "sceKernelEnableSubIntr", &Kernel::sceKernelEnableSubIntr);
    hle(im, 0x8A389411u, "sceKernelDisableSubIntr", &Kernel::sceKernelDisableSubIntr);
    hle(tm, 0x6652B8CAu, "sceKernelSetAlarm", &Kernel::sceKernelSetAlarm);
    hle(tm, 0xB2C25152u, "sceKernelSetSysClockAlarm", &Kernel::sceKernelSetSysClockAlarm);
    hle(tm, 0x7E65B999u, "sceKernelCancelAlarm", &Kernel::sceKernelCancelAlarm);
    hle(tm, 0x28B6489Cu, "sceKernelDeleteSema", &Kernel::sceKernelDeleteSema);
    hle(tm, 0x3F53E640u, "sceKernelSignalSema", &Kernel::sceKernelSignalSema);
    hle(tm, 0x4E3A1105u, "sceKernelWaitSema", &Kernel::sceKernelWaitSema);
    hle(tm, 0x6D212BACu, "sceKernelWaitSemaCB", &Kernel::sceKernelWaitSema);
    hle(tm, 0x58B1F937u, "sceKernelPollSema", &Kernel::sceKernelPollSema);
    hle(tm, 0x55C20A00u, "sceKernelCreateEventFlag", &Kernel::sceKernelCreateEventFlag);
    hle(tm, 0xEF9E4C70u, "sceKernelDeleteEventFlag", &Kernel::sceKernelDeleteEventFlag);
    hle(tm, 0x1FB15A32u, "sceKernelSetEventFlag", &Kernel::sceKernelSetEventFlag);
    hle(tm, 0x812346E4u, "sceKernelClearEventFlag", &Kernel::sceKernelClearEventFlag);
    hle(tm, 0x402FCF22u, "sceKernelWaitEventFlag", &Kernel::sceKernelWaitEventFlag);
    hle(tm, 0x328C546Au, "sceKernelWaitEventFlagCB", &Kernel::sceKernelWaitEventFlag);
    hle(tm, 0x30FD48F0u, "sceKernelPollEventFlag", &Kernel::sceKernelPollEventFlag);
    hle(tm, 0x912354A7u, "sceKernelRotateThreadReadyQueue", &Kernel::sceKernelRotateThreadReadyQueue);

    const char *sm = "SysMemUserForUser";
    hle(sm, 0xA291F107u, "sceKernelMaxFreeMemSize", &Kernel::sceKernelMaxFreeMemSize);
    hle(sm, 0xF919F628u, "sceKernelTotalFreeMemSize", &Kernel::sceKernelTotalFreeMemSize);
    hle(sm, 0x237DBD4Fu, "sceKernelAllocPartitionMemory", &Kernel::sceKernelAllocPartitionMemory);
    hle(sm, 0xB6D61D02u, "sceKernelFreePartitionMemory", &Kernel::sceKernelFreePartitionMemory);
    hle(sm, 0x9D9A5BA1u, "sceKernelGetBlockHeadAddr", &Kernel::sceKernelGetBlockHeadAddr);
    hle(sm, 0x3FC9AE6Au, "sceKernelDevkitVersion", &Kernel::sceKernelDevkitVersion);
    hle(sm, 0x13A5ABEFu, "sceKernelPrintf", &Kernel::sceKernelPrintf);
    hle(sm, 0x7591C7DBu, "sceKernelSetCompiledSdkVersion", &Kernel::return_zero);
    hle(sm, 0xF77D77CBu, "sceKernelSetCompilerVersion", &Kernel::return_zero);

    hle("LoadExecForUser", 0x05572A5Fu, "sceKernelExitGame", &Kernel::sceKernelExitGame);
    hle("LoadExecForUser", 0x2AC9954Bu, "sceKernelExitGameWithStatus", &Kernel::sceKernelExitGame);
    hle("LoadExecForUser", 0x4AC57943u, "sceKernelRegisterExitCallback", &Kernel::sceKernelRegisterExitCallback);

    const char *mm = "ModuleMgrForUser";
    hle(mm, 0xD675EBB8u, "sceKernelSelfStopUnloadModule", &Kernel::sceKernelSelfStopUnloadModule);
    hle(mm, 0x977DE386u, "sceKernelLoadModule", &Kernel::sceKernelLoadModule);
    hle(mm, 0x50F0C1ECu, "sceKernelStartModule", &Kernel::sceKernelStartModule);
    hle(mm, 0xD1FF982Au, "sceKernelStopModule", &Kernel::sceKernelStopModule);
    hle(mm, 0x2E0911AAu, "sceKernelUnloadModule", &Kernel::sceKernelUnloadModule);
    hle(mm, 0x8F2DF740u, "sceKernelStopUnloadSelfModuleWithStatus", &Kernel::sceKernelStopUnloadSelfModuleWithStatus);
    hle(mm, 0xD8B73127u, "sceKernelGetModuleIdByAddress", &Kernel::sceKernelGetModuleIdByAddress);
    hle(mm, 0xF0A26395u, "sceKernelGetModuleId", &Kernel::sceKernelGetModuleId);
    hle(mm, 0x748CBED9u, "sceKernelQueryModuleInfo", &Kernel::sceKernelQueryModuleInfo);
    hle(mm, 0x644395E2u, "sceKernelGetModuleIdList", &Kernel::sceKernelGetModuleIdList);

    hle("StdioForUser", 0x172D316Eu, "sceKernelStdin", &Kernel::sceKernelStdin);
    hle("StdioForUser", 0xA6BAB2E9u, "sceKernelStdout", &Kernel::sceKernelStdout);
    hle("StdioForUser", 0xF78BA90Au, "sceKernelStderr", &Kernel::sceKernelStderr);

    const char *io = "IoFileMgrForUser";
    hle(io, 0x109F50BCu, "sceIoOpen", &Kernel::sceIoOpen);
    hle(io, 0x810C4BC3u, "sceIoClose", &Kernel::sceIoClose);
    hle(io, 0x6A638D83u, "sceIoRead", &Kernel::sceIoRead);
    hle(io, 0x63632449u, "sceIoIoctl", &Kernel::sceIoIoctl);
    hle(io, 0xB293727Fu, "sceIoChangeAsyncPriority", &Kernel::return_zero);
    hle(io, 0x42EC03ACu, "sceIoWrite", &Kernel::sceIoWrite);
    hle(io, 0x27EB27B8u, "sceIoLseek", &Kernel::sceIoLseek);
    hle(io, 0x68963324u, "sceIoLseek32", &Kernel::sceIoLseek32);
    hle(io, 0xACE946E8u, "sceIoGetstat", &Kernel::sceIoGetstat);
    hle(io, 0x55F4717Du, "sceIoChdir", &Kernel::sceIoChdir);
    hle(io, 0xB29DDF9Cu, "sceIoDopen", &Kernel::sceIoDopen);
    hle(io, 0xE3EB004Cu, "sceIoDread", &Kernel::sceIoDread);
    hle(io, 0xEB092469u, "sceIoDclose", &Kernel::sceIoDclose);
    hle(io, 0x89AA9906u, "sceIoOpenAsync", &Kernel::sceIoOpenAsync);
    hle(io, 0xA0B5A7C2u, "sceIoReadAsync", &Kernel::sceIoReadAsync);
    hle(io, 0x71B19E77u, "sceIoLseekAsync", &Kernel::sceIoLseekAsync);
    hle(io, 0xFF5940B6u, "sceIoCloseAsync", &Kernel::sceIoCloseAsync);
    hle(io, 0xE23EEC33u, "sceIoWaitAsync", &Kernel::sceIoWaitAsync);
    hle(io, 0x35DBD746u, "sceIoWaitAsyncCB", &Kernel::sceIoWaitAsync);
    hle(io, 0x3251EA56u, "sceIoPollAsync", &Kernel::sceIoPollAsync);
    hle(io, 0x1B385D8Fu, "sceIoLseek32Async", &Kernel::sceIoLseek32Async);
    hle(io, 0xA12A0514u, "sceIoSetAsyncCallback", &Kernel::sceIoSetAsyncCallback);

    const char *dp = "sceDisplay";
    hle(dp, 0x0E20F177u, "sceDisplaySetMode", &Kernel::sceDisplaySetMode);
    hle(dp, 0x289D82FEu, "sceDisplaySetFrameBuf", &Kernel::sceDisplaySetFrameBuf);
    hle(dp, 0xEEDA2E54u, "sceDisplayGetFrameBuf", &Kernel::sceDisplayGetFrameBuf);
    hle(dp, 0x984C27E7u, "sceDisplayWaitVblankStart", &Kernel::sceDisplayWaitVblankStart);
    hle(dp, 0x46F186C3u, "sceDisplayWaitVblankStartCB", &Kernel::sceDisplayWaitVblankStart);
    hle(dp, 0x36CDFADEu, "sceDisplayWaitVblank", &Kernel::sceDisplayWaitVblankStart);
    hle(dp, 0x8EB9EC49u, "sceDisplayWaitVblankCB", &Kernel::sceDisplayWaitVblankStart);
    hle(dp, 0x9C6EAAD7u, "sceDisplayGetVcount", &Kernel::sceDisplayGetVcount);

    hle("sceGe_user", 0xE47E40E4u, "sceGeEdramGetAddr", &Kernel::sceGeEdramGetAddr);
    hle("sceGe_user", 0x1F6752ADu, "sceGeEdramGetSize", &Kernel::sceGeEdramGetSize);
    hle("sceGe_user", 0xAB49E76Au, "sceGeListEnQueue", &Kernel::sceGeListEnQueue);
    hle("sceGe_user", 0x1C0D95A6u, "sceGeListEnQueueHead", &Kernel::sceGeListEnQueue);
    hle("sceGe_user", 0xE0D68148u, "sceGeListUpdateStallAddr", &Kernel::sceGeListUpdateStallAddr);
    hle("sceGe_user", 0x03444EB4u, "sceGeListSync", &Kernel::sceGeListSync);
    hle("sceGe_user", 0xB287BD61u, "sceGeDrawSync", &Kernel::sceGeDrawSync);
    hle("sceGe_user", 0x4C06E472u, "sceGeContinue", &Kernel::return_zero);
    hle("sceGe_user", 0xB448EC0Du, "sceGeBreak", &Kernel::return_zero);
    hle("sceGe_user", 0xA4FC06A4u, "sceGeSetCallback", &Kernel::sceGeSetCallback);
    hle("sceGe_user", 0x05DB22CEu, "sceGeUnsetCallback", &Kernel::sceGeUnsetCallback);
    hle("sceGe_user", 0xB77905EAu, "sceGeEdramSetAddrTranslation", &Kernel::return_zero);
    hle("sceGe_user", 0xDC93CFEFu, "sceGeGetCmd", &Kernel::sceGeGetCmd);
    hle("sceGe_user", 0x438A385Au, "sceGeSaveContext", &Kernel::sceGeSaveContext);
    hle("sceGe_user", 0x0BF608FBu, "sceGeRestoreContext", &Kernel::sceGeRestoreContext);

    const char *ut = "UtilsForUser";
    hle(ut, 0x27CC57F0u, "sceKernelLibcTime", &Kernel::sceKernelLibcTime);
    hle(ut, 0x71EC4271u, "sceKernelLibcGettimeofday", &Kernel::sceKernelLibcGettimeofday);
    hle(ut, 0x79D1C3FAu, "sceKernelDcacheWritebackAll", &Kernel::return_zero);
    hle(ut, 0xB435DEC5u, "sceKernelDcacheWritebackInvalidateAll", &Kernel::return_zero);
    hle(ut, 0x3EE30821u, "sceKernelDcacheWritebackRange", &Kernel::return_zero);
    hle(ut, 0x34B9FA9Eu, "sceKernelDcacheWritebackInvalidateRange", &Kernel::return_zero);
    hle(ut, 0xBFA98062u, "sceKernelDcacheInvalidateRange", &Kernel::return_zero);
    hle(ut, 0x920F104Au, "sceKernelIcacheInvalidateAll", &Kernel::return_zero);
    hle(ut, 0x6AD345D7u, "sceKernelSetGPO", &Kernel::return_zero);

    hle("Kernel_Library", 0x092968F4u, "sceKernelCpuSuspendIntr", &Kernel::sceKernelCpuSuspendIntr);
    hle("Kernel_Library", 0x5F10D406u, "sceKernelCpuResumeIntr", &Kernel::return_zero);
    hle("Kernel_Library", 0x3B84732Du, "sceKernelCpuResumeIntrWithSync", &Kernel::return_zero);
    hle("Kernel_Library", 0x293B45B8u, "sceKernelGetThreadId", &Kernel::sceKernelGetThreadId);
    hle("Kernel_Library", 0x1839852Au, "sceKernelMemcpy", &Kernel::sceKernelMemcpy);
    hle("Kernel_Library", 0xA089ECA4u, "sceKernelMemset", &Kernel::sceKernelMemset);

    install_devices();
    install_mpeg();
    install_sas();
    install_atrac();
    install_fonts();
    install_savedata();
    install_cheats();
    for (const auto &import : imports) install_fallback(import);
}

// ---------------------------------------------------------------------------
// Scheduling

Thread *Kernel::current() {
    const auto it = threads_.find(current_uid_);
    return it == threads_.end() ? nullptr : &it->second;
}

Thread *Kernel::thread(std::int32_t uid) {
    if (uid == 0) return current();
    const auto it = threads_.find(uid);
    return it == threads_.end() ? nullptr : &it->second;
}

void Kernel::make_ready(Thread &t, bool front) {
    t.state = ThreadState::Ready;
    t.wait = WaitType::None;
    t.ready_sequence = front ? 0u : ++ready_sequence_;
}

Thread *Kernel::pick_ready() {
    Thread *best = nullptr;
    for (auto &[uid, t] : threads_) {
        (void)uid;
        if (t.state != ThreadState::Ready) continue;
        if (best == nullptr || t.priority < best->priority ||
            (t.priority == best->priority && t.ready_sequence < best->ready_sequence))
            best = &t;
    }
    return best;
}

void Kernel::load_thread(Thread &t) {
    rt_.cpu() = t.ctx;
    t.state = ThreadState::Running;
    current_uid_ = t.uid;
    psprecomp::set_runtime_thread_identity(t.uid, t.name);
}

void Kernel::reset_context(Ctx &ctx) const {
    ctx = Ctx{};
    ctx.fcr31 = 0x00000E00u;
    ctx.vfpu_ctrl[0] = 0xE4u; // PFXS identity swizzle
    ctx.vfpu_ctrl[1] = 0xE4u; // PFXT identity swizzle
    ctx.vfpu_ctrl[2] = 0u;    // PFXD
    ctx.vfpu_ctrl[3] = 0x3Fu; // CC
}

void Kernel::block(Ctx &ctx, WaitType wait, std::uint32_t result) {
    Thread *t = current();
    finish(ctx, result);
    if (t == nullptr) {
        rt_.stop("idle");
        return;
    }
    t->ctx = ctx;
    t->state = ThreadState::Waiting;
    t->wait = wait;
    reschedule(ctx);
}

void Kernel::reschedule(Ctx &ctx) {
    poll_waits();
    Thread *next = pick_ready();
    if (next == nullptr) {
        current_uid_ = -1;
        psprecomp::set_runtime_thread_identity(-1, "idle");
        rt_.stop("idle");
        return;
    }
    ctx = next->ctx;
    next->state = ThreadState::Running;
    current_uid_ = next->uid;
    psprecomp::set_runtime_thread_identity(next->uid, next->name);
}

void Kernel::maybe_preempt(Ctx &ctx) {
    Thread *cur = current();
    Thread *best = pick_ready();
    if (cur == nullptr || best == nullptr || best->priority >= cur->priority) return;
    cur->ctx = ctx;
    make_ready(*cur, true);
    reschedule(ctx);
}

void Kernel::wake(Thread &t, std::uint32_t result) {
    t.ctx.gpr[2] = result;
    if (t.timeout_address != 0u) {
        const std::uint64_t now = now_us();
        rt_.memory().store32(t.timeout_address,
                             t.wake_time_us > now ? static_cast<std::uint32_t>(t.wake_time_us - now) : 0u);
    }
    t.wake_time_us = 0u;
    t.timeout_address = 0u;
    make_ready(t);
}

void Kernel::begin_timeout(Thread &t, std::uint32_t timeout_address) {
    t.timeout_address = timeout_address;
    t.wake_time_us = timeout_address != 0u ? now_us() + rt_.memory().load32(timeout_address) : 0u;
}

void Kernel::poll_waits() {
    const std::uint64_t now = now_us();
    for (auto &[uid, t] : threads_) {
        (void)uid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::Ge && ge_worker_->done(t.wait_count)) {
            wake(t, 0u);
            continue;
        }
        if (t.state != ThreadState::Waiting || t.wake_time_us == 0u || now < t.wake_time_us) continue;
        if (t.wait == WaitType::Delay) {
            t.wake_time_us = 0u;
            wake(t, 0u);
        } else if (t.wait == WaitType::Sema || t.wait == WaitType::EventFlag || t.wait == WaitType::ThreadEnd ||
                   t.wait == WaitType::Fpl || t.wait == WaitType::Mutex || t.wait == WaitType::Mbx) {
            wake(t, kErrorWaitTimeout);
        }
    }
}

bool Kernel::waiting_for_ge() const {
    for (const auto &[uid, t] : threads_) {
        (void)uid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::Ge) return true;
    }
    return false;
}

bool Kernel::waiting_for_io() const {
    for (const auto &[uid, t] : threads_) {
        (void)uid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::Io) return true;
    }
    return false;
}

std::uint64_t Kernel::earliest_timed_wake() const {
    std::uint64_t earliest = 0u;
    for (const auto &[uid, t] : threads_) {
        (void)uid;
        if (t.state == ThreadState::Waiting && t.wake_time_us != 0u &&
            (earliest == 0u || t.wake_time_us < earliest))
            earliest = t.wake_time_us;
    }
    for (const auto &[uid, alarm] : alarms_) {
        (void)uid;
        if (alarm.running == 0 && (earliest == 0u || alarm.at < earliest)) earliest = alarm.at;
    }
    return earliest;
}

void Kernel::start_thread(Thread &t, std::uint32_t arglen, const std::vector<std::uint8_t> &args) {
    reset_context(t.ctx);
    std::uint32_t sp = t.stack_top - 0x100u; // k0 area at the stack top
    for (std::uint32_t i = 0; i < 0x100u; i += 4u) rt_.memory().store32(sp + i, 0u);
    t.ctx.gpr[26] = sp; // k0
    std::uint32_t argp = 0u;
    if (arglen != 0u && !args.empty()) {
        sp -= align_up(arglen, 16u);
        for (std::uint32_t i = 0; i < arglen && i < args.size(); ++i) rt_.memory().store8(sp + i, args[i]);
        argp = sp;
    }
    sp -= 64u;
    t.ctx.gpr[4] = arglen;
    t.ctx.gpr[5] = argp;
    t.ctx.gpr[28] = t.gp;
    t.ctx.gpr[29] = sp;
    t.ctx.gpr[31] = kThreadReturnAddress;
    t.ctx.pc = t.entry;
    t.wakeup_count = 0u;
    make_ready(t);
}

void Kernel::exit_thread(Ctx &ctx, std::int32_t status, bool remove) {
    Thread *t = current();
    if (t == nullptr) {
        rt_.stop("idle");
        return;
    }
    t->exit_status = status;
    t->state = remove ? ThreadState::Dead : ThreadState::Dormant;
    if (remove && t->stack_block >= 0) {
        blocks_.erase(t->stack_block);
        t->stack_block = -1;
    }
    const std::int32_t uid = t->uid;
    for (auto &[other_uid, other] : threads_) {
        (void)other_uid;
        if (other.state == ThreadState::Waiting && other.wait == WaitType::ThreadEnd && other.wait_uid == uid)
            wake(other, static_cast<std::uint32_t>(status));
    }
    if (const auto call = guest_calls_.find(uid); call != guest_calls_.end()) {
        // A guest callback finished: hand its result to the thread waiting for it.
        t->state = ThreadState::Dead;
        if (t->stack_block >= 0) {
            blocks_.erase(t->stack_block);
            t->stack_block = -1;
        }
        Thread *caller = thread(call->second.caller);
        const std::uint32_t result = call->second.done ? call->second.done(static_cast<std::uint32_t>(status))
                                                       : static_cast<std::uint32_t>(status);
        guest_calls_.erase(call);
        threads_.erase(uid);
        if (caller != nullptr && caller->state == ThreadState::Waiting && caller->wait == WaitType::Callback)
            wake(*caller, result);
    }
    reschedule(ctx);
}

void Kernel::call_guest(Ctx &ctx, std::uint32_t entry, std::initializer_list<std::uint32_t> args,
                        std::function<std::uint32_t(std::uint32_t)> done, std::uint32_t gp,
                        std::uint32_t stack_size) {
    Thread *caller = current();
    if (caller == nullptr || entry == 0u) {
        finish(ctx, done ? done(0u) : 0u);
        return;
    }
    Thread t;
    t.uid = new_uid();
    t.name = "pspweb_callback";
    t.entry = entry;
    t.priority = caller->priority;
    t.stack_size = stack_size;
    t.stack_block = allocate("stack:callback", 1u, t.stack_size, 0u);
    if (t.stack_block < 0) {
        finish(ctx, done ? done(0u) : 0u);
        return;
    }
    t.stack_top = blocks_.at(t.stack_block).address + t.stack_size;
    t.gp = gp != 0u ? gp : ctx.gpr[28];
    const std::int32_t uid = t.uid;
    auto &stored = threads_[uid] = std::move(t);
    start_thread(stored, 0u, {});
    std::uint32_t reg = 4u;
    for (const std::uint32_t value : args) stored.ctx.gpr[reg++] = value;
    make_ready(stored, true);
    guest_calls_[uid] = GuestCall{caller->uid, std::move(done)};
    block(ctx, WaitType::Callback, 0u);
}

void Kernel::dump_threads() const {
    static const char *states[] = {"dormant", "ready", "running", "waiting", "dead"};
    static const char *waits[] = {"-", "sleep", "delay", "vblank", "thread-end", "sema", "event-flag", "fpl", "io", "callback", "ge", "mutex", "mbx", "ctrl"};
    for (const auto &[uid, t] : threads_) {
        const auto &c = uid == current_uid_ ? rt_.cpu() : t.ctx;
        std::cerr << "[thread] " << uid << " " << t.name << " prio=" << t.priority << " "
                  << states[static_cast<int>(t.state)] << " wait=" << waits[static_cast<int>(t.wait)]
                  << " on=" << t.wait_uid << " pc=" << hex(c.pc) << " ra=" << hex(c.gpr[31]) << "\n";
    }
    for (const auto &[uid, s] : semaphores_)
        std::cerr << "[sema] " << uid << " " << s.name << " count=" << s.count << "\n";
    for (const auto &[uid, e] : event_flags_)
        std::cerr << "[event] " << uid << " " << e.name << " pattern=" << hex(e.pattern) << "\n";
}

void Kernel::thread_returned(Ctx &ctx) {
    exit_thread(ctx, static_cast<std::int32_t>(ctx.gpr[2]), false);
}

void Kernel::boot(std::uint32_t entry, std::uint32_t gp, const std::string &module_path) {
    Thread t;
    t.uid = new_uid();
    t.name = "pspweb_loader";
    t.entry = entry;
    t.priority = 0x20;
    t.stack_size = 0x40000u;
    t.stack_block = allocate("stack:" + t.name, 1u, t.stack_size, 0u);
    t.stack_top = blocks_.at(t.stack_block).address + t.stack_size;
    t.gp = gp;
    std::vector<std::uint8_t> args(module_path.begin(), module_path.end());
    args.push_back(0u);
    auto &stored = threads_[t.uid] = std::move(t);
    start_thread(stored, static_cast<std::uint32_t>(args.size()), args);
}

bool Kernel::frame(double budget_ms) {
    if (halted_) return false;
    const std::uint64_t prev_now_us = display_.vcount > 1u ? now_us() : 0u;
    poll_io();
    ++display_.vcount;
    ge_worker_->post([ge = ge_.get()] { ge->next_frame(); });
    frame_start_guest_us_ = std::max(static_cast<std::uint64_t>(display_.vcount) * kFrameUs, prev_now_us);
    frame_real_start_ns_ = real_now_ns();
    warp_us_ = 0u;
    // Apply cheats at the very top of the frame, before any guest thread runs, so
    // a poke is visible to the code that executes this frame.  freeze_clock is a
    // state: it is cleared here and re-requested by the action while it is on, so
    // disabling the cheat releases the clock on the next frame.  The held value is
    // captured on the frame the freeze begins and stays put while it lasts.
    if (cheats_.any_enabled()) {
        const bool was_frozen = cheat_freeze_clock_;
        cheat_freeze_clock_ = false;
        cheats_.apply_frame();
        if (cheat_freeze_clock_ && !was_frozen) cheat_frozen_us_ = frame_start_guest_us_;
    } else {
        cheat_freeze_clock_ = false;
    }
    for (auto &[uid, t] : threads_) {
        (void)uid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::Vblank) wake(t, 0u);
        if (t.state == ThreadState::Waiting && t.wait == WaitType::CtrlRead) {
            write_pad(t.wait_out_address, t.wait_count);
            pad_read_vcount_ = display_.vcount;
            wake(t, t.wait_count);
        }
    }
    run_interrupts(kVblankInterrupt);
    // VBlank fired: mark all enabled callbacks as pending so
    // sceKernelCheckCallback can dispatch them to the game.
    for (auto &[uid, cb] : callbacks_) {
        if (cb.enabled && !cb.exit_only && !cb.pending && cb.running == 0) cb.pending = true;
    }

    const auto deadline = Clock::now() + std::chrono::microseconds(static_cast<std::int64_t>(budget_ms * 1000.0));
    while (!halted_ && Clock::now() < deadline) {
        poll_waits();
        run_alarms();
        run_ge_callbacks();
        if (Thread *running = current()) {
            const Thread *next = pick_ready();
            if (next != nullptr && next->priority < running->priority) {
                running->ctx = rt_.cpu();
                make_ready(*running, true);
                current_uid_ = -1;
            }
        }
        if (current() == nullptr) {
            Thread *next = pick_ready();
            if (next == nullptr && waiting_for_ge()) {
                // The GE is drawing on its own thread: let real time pass
                // (no warping) until it finishes something or a timer is due.
                const auto waited_from = Clock::now();
                ge_worker_->wait_for_progress(0.25);
                ge_wait_ms_ += std::chrono::duration<double, std::milli>(Clock::now() - waited_from).count();
                continue;
            }
            if (next == nullptr) {
                if (waiting_for_io()) {
                    poll_io();
                    next = pick_ready();
                    if (next == nullptr) break;
                } else {
                    const std::uint64_t wake_at = earliest_timed_wake();
                    const std::uint64_t now = now_us();
                    const std::uint64_t frame_end_us =
                        std::max(frame_start_guest_us_, static_cast<std::uint64_t>(display_.vcount) * kFrameUs) + kFrameUs - 1u;
                    if (wake_at != 0u && wake_at < frame_end_us) {
                        if (wake_at > now) warp_us_ += wake_at - now;
                        continue;
                    }
                    break;
                }
            }
            load_thread(*next);
        }

        g_slice_deadline = deadline;
        try {
            rt_.run(rt_.cpu().pc, std::numeric_limits<std::uint64_t>::max());
        } catch (const std::exception &e) {
            halted_ = true;
            halt_reason_ = e.what();
            break;
        }
        const std::string &reason = rt_.stop_reason();
        if (reason == "idle" || reason == "interrupt") continue;
        if (reason == "slice") break;
        halted_ = true;
        halt_reason_ = reason;
    }

    drain_audio(frame_start_guest_us_ + kFrameUs);
    if (halted_) {
        std::cerr << "[kernel] halted: " << halt_reason_ << "\n";
        dump_diagnosis("halt");
        return false;
    }
    // Progress watchdog: if the guest keeps running frames but never reaches a
    // new HLE call, it is spinning in guest code that polls something the host
    // never satisfies.  Report the blocking state once so a silent browser hang
    // is diagnosable.  PSPWEB_STALL_FRAMES overrides the threshold.
    static const int stall_frames = [] {
        if (const char *env = std::getenv("PSPWEB_STALL_FRAMES"); env != nullptr && *env != '\0')
            return std::max(1, std::atoi(env));
        return 120;
    }();
    if (hle_calls_ != last_progress_hle_calls_) {
        last_progress_hle_calls_ = hle_calls_;
        idle_frames_ = 0;
        diagnosed_ = false;
    } else if (++idle_frames_ >= stall_frames && !diagnosed_) {
        diagnosed_ = true;
        dump_diagnosis("stalled");
    }
    for (const auto &[uid, t] : threads_) {
        (void)uid;
        if (t.state == ThreadState::Ready || t.state == ThreadState::Running || t.state == ThreadState::Waiting)
            return true;
    }
    halt_reason_ = "no threads left";
    return false;
}

namespace {
const char *wait_name(WaitType w) {
    switch (w) {
    case WaitType::None: return "none";
    case WaitType::Sleep: return "sleep";
    case WaitType::Delay: return "delay";
    case WaitType::Vblank: return "vblank";
    case WaitType::ThreadEnd: return "thread-end";
    case WaitType::Sema: return "semaphore";
    case WaitType::EventFlag: return "event-flag";
    case WaitType::Fpl: return "fpl";
    case WaitType::Io: return "io";
    case WaitType::Callback: return "callback";
    case WaitType::Ge: return "ge";
    case WaitType::Mutex: return "mutex";
    case WaitType::Mbx: return "mbx";
    case WaitType::CtrlRead: return "ctrl";
    }
    return "?";
}
const char *state_name(ThreadState s) {
    switch (s) {
    case ThreadState::Dormant: return "dormant";
    case ThreadState::Ready: return "ready";
    case ThreadState::Running: return "running";
    case ThreadState::Waiting: return "waiting";
    case ThreadState::Dead: return "dead";
    }
    return "?";
}
} // namespace

// Prints everything needed to identify a silent hang: each live thread's state,
// what it waits on, and the last HLE call it made, plus open files and the
// semaphores a waiter could be blocked on.
void Kernel::dump_diagnosis(const char *reason) {
    const std::string tag = std::string("[") + reason + "]";
    std::cerr << tag << " guest has made no HLE progress for " << idle_frames_ << " frames"
              << " (hle calls total " << hle_calls_ << ", vcount " << display_.vcount << ")\n";
    // Frame counter and display register state: a game that never reaches a
    // framebuffer flip (or one that never leaves a black buffer up) is a
    // different bug from one that hangs inside a frame, and the log above has
    // to tell them apart without a rebuild.
    std::cerr << tag << " display: vcount=" << display_.vcount << " flips=" << display_.flips
              << " framebuffer=0x" << std::hex << display_.framebuffer << std::dec
              << " stride=" << display_.stride << " format=" << display_.format << "\n";
    std::cerr << tag << " threads:\n";
    for (const auto &[uid, t] : threads_) {
        std::cerr << tag << "   " << uid << " " << t.name << " prio=" << t.priority << " " << state_name(t.state)
                  << " wait=" << wait_name(t.wait);
        // Vblank, CtrlRead and Ge also hold a count worth seeing (the GE list
        // id, for instance), so only the two wait types that never print one
        // are skipped.
        if (t.state == ThreadState::Waiting && t.wait != WaitType::Delay && t.wait != WaitType::Sleep) {
            std::cerr << " on=0x" << std::hex << t.wait_uid << std::dec << " count=" << t.wait_count;
        }
        if (auto it = last_hle_.find(uid); it != last_hle_.end()) std::cerr << " last-hle=" << it->second;
        std::cerr << " pc=0x" << std::hex << t.ctx.pc << " ra=0x" << t.ctx.gpr[31] << std::dec << "\n";
    }
    if (!semaphores_.empty()) {
        std::cerr << tag << " semaphores:\n";
        for (const auto &[uid, s] : semaphores_) {
            std::cerr << tag << "   " << uid << " " << s.name << " count=" << s.count << " max=" << s.max << "\n";
        }
    }
    if (!files_.empty()) {
        std::cerr << tag << " open files: " << files_.size() << ", last=";
        if (!files_.rbegin()->second.path.empty()) std::cerr << files_.rbegin()->second.path;
        std::cerr << "\n";
    }
    std::cerr << tag << " hint: a thread waiting on a semaphore/event-flag/thread-end that no other thread can signal"
              << " is the usual boot hang; compare each waiter's wait target against what is still alive above.\n";
}

// ---------------------------------------------------------------------------
// Memory

void Kernel::reserve(std::uint32_t address, std::uint32_t size, std::string name) {
    blocks_[new_uid()] = MemoryBlock{std::move(name), address, align_up(size, 0x100u)};
}

std::int32_t Kernel::allocate(std::string name, std::uint32_t type, std::uint32_t size, std::uint32_t address) {
    size = align_up(std::max(size, 1u), 0x100u);
    std::vector<std::pair<std::uint32_t, std::uint32_t>> used;
    for (const auto &[uid, block] : blocks_) {
        (void)uid;
        used.emplace_back(block.address, block.address + block.size);
    }
    std::sort(used.begin(), used.end());
    // Free gaps between used ranges inside the user partition.
    std::vector<std::pair<std::uint32_t, std::uint32_t>> gaps;
    std::uint32_t cursor = kUserPartitionStart;
    for (const auto &[begin, end] : used) {
        if (begin > cursor) gaps.emplace_back(cursor, begin);
        cursor = std::max(cursor, end);
    }
    if (cursor < kUserPartitionEnd) gaps.emplace_back(cursor, kUserPartitionEnd);

    std::uint32_t chosen = 0u;
    if (type == 2u) { // fixed address
        const std::uint32_t wanted = align_up(address, 0x100u);
        for (const auto &[begin, end] : gaps)
            if (wanted >= begin && wanted + size <= end) chosen = wanted;
    } else if (type == 1u) { // high
        for (auto it = gaps.rbegin(); it != gaps.rend() && chosen == 0u; ++it)
            if (it->second - it->first >= size) chosen = (it->second - size) & ~0xFFu;
    } else { // low
        for (const auto &[begin, end] : gaps)
            if (chosen == 0u && end - begin >= size) chosen = begin;
    }
    if (chosen == 0u) return -1;
    const std::int32_t uid = new_uid();
    blocks_[uid] = MemoryBlock{std::move(name), chosen, size};
    return uid;
}

std::uint32_t Kernel::largest_free() const {
    std::vector<std::pair<std::uint32_t, std::uint32_t>> used;
    for (const auto &[uid, block] : blocks_) {
        (void)uid;
        used.emplace_back(block.address, block.address + block.size);
    }
    std::sort(used.begin(), used.end());
    std::uint32_t cursor = kUserPartitionStart, largest = 0u;
    for (const auto &[begin, end] : used) {
        if (begin > cursor) largest = std::max(largest, begin - cursor);
        cursor = std::max(cursor, end);
    }
    if (cursor < kUserPartitionEnd) largest = std::max(largest, kUserPartitionEnd - cursor);
    return largest;
}

std::uint32_t Kernel::total_free() const {
    std::uint32_t used = 0u;
    for (const auto &[uid, block] : blocks_) {
        (void)uid;
        used += block.size;
    }
    const std::uint32_t total = kUserPartitionEnd - kUserPartitionStart;
    return used < total ? total - used : 0u;
}

// ---------------------------------------------------------------------------
// ThreadManForUser

void Kernel::sceKernelCreateThread(Ctx &ctx) {
    Thread t;
    t.uid = new_uid();
    t.name = read_string(ctx.gpr[4], 32);
    t.entry = ctx.gpr[5];
    t.priority = static_cast<std::int32_t>(ctx.gpr[6]);
    t.stack_size = align_up(std::max(ctx.gpr[7], 0x200u), 0x100u);
    t.attr = ctx.gpr[8];
    t.stack_block = allocate("stack:" + t.name, 1u, t.stack_size, 0u);
    if (t.stack_block < 0) {
        finish(ctx, kErrorNoMemory);
        return;
    }
    t.stack_top = blocks_.at(t.stack_block).address + t.stack_size;
    t.gp = ctx.gpr[28];
    const std::int32_t uid = t.uid;
    threads_[uid] = std::move(t);
    finish(ctx, static_cast<std::uint32_t>(uid));
}

void Kernel::sceKernelStartThread(Ctx &ctx) {
    Thread *t = thread(static_cast<std::int32_t>(ctx.gpr[4]));
    if (t == nullptr) {
        finish(ctx, kErrorUnknownThread);
        return;
    }
    if (t->state != ThreadState::Dormant) {
        finish(ctx, kErrorNotDormant);
        return;
    }
    const std::uint32_t arglen = ctx.gpr[5], argp = ctx.gpr[6];
    std::vector<std::uint8_t> args;
    if (argp != 0u)
        for (std::uint32_t i = 0; i < arglen; ++i) args.push_back(rt_.memory().load8(argp + i));
    start_thread(*t, args.empty() ? 0u : arglen, args);
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

void Kernel::sceKernelExitThread(Ctx &ctx) { exit_thread(ctx, static_cast<std::int32_t>(ctx.gpr[4]), false); }
void Kernel::sceKernelExitDeleteThread(Ctx &ctx) { exit_thread(ctx, static_cast<std::int32_t>(ctx.gpr[4]), true); }

void Kernel::sceKernelDeleteThread(Ctx &ctx) {
    Thread *t = thread(static_cast<std::int32_t>(ctx.gpr[4]));
    if (t == nullptr) {
        finish(ctx, kErrorUnknownThread);
        return;
    }
    if (t->stack_block >= 0) blocks_.erase(t->stack_block);
    t->stack_block = -1;
    t->state = ThreadState::Dead;
    finish(ctx, 0u);
}

void Kernel::sceKernelTerminateDeleteThread(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    if (uid == current_uid_ || uid == 0) {
        exit_thread(ctx, 0, true);
        return;
    }
    sceKernelDeleteThread(ctx);
}

void Kernel::sceKernelSleepThread(Ctx &ctx) {
    Thread *t = current();
    if (t != nullptr && t->wakeup_count > 0u) {
        --t->wakeup_count;
        finish(ctx, 0u);
        return;
    }
    block(ctx, WaitType::Sleep, 0u);
}

void Kernel::sceKernelWakeupThread(Ctx &ctx) {
    Thread *t = thread(static_cast<std::int32_t>(ctx.gpr[4]));
    if (t == nullptr) {
        finish(ctx, kErrorUnknownThread);
        return;
    }
    if (t->state == ThreadState::Waiting && t->wait == WaitType::Sleep) wake(*t, 0u);
    else ++t->wakeup_count;
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

void Kernel::sceKernelDelayThread(Ctx &ctx) {
    Thread *t = current();
    if (t != nullptr) t->wake_time_us = now_us() + std::max(ctx.gpr[4], 1u);
    block(ctx, WaitType::Delay, 0u);
}

void Kernel::sceKernelGetThreadId(Ctx &ctx) { finish(ctx, static_cast<std::uint32_t>(current_uid_)); }

void Kernel::sceKernelGetThreadCurrentPriority(Ctx &ctx) {
    Thread *t = current();
    finish(ctx, t != nullptr ? static_cast<std::uint32_t>(t->priority) : 0x20u);
}

void Kernel::sceKernelChangeThreadPriority(Ctx &ctx) {
    Thread *t = thread(static_cast<std::int32_t>(ctx.gpr[4]));
    if (t == nullptr) {
        finish(ctx, kErrorUnknownThread);
        return;
    }
    if (ctx.gpr[5] != 0u) t->priority = static_cast<std::int32_t>(ctx.gpr[5]);
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

void Kernel::sceKernelWaitThreadEnd(Ctx &ctx) {
    Thread *target = thread(static_cast<std::int32_t>(ctx.gpr[4]));
    if (target == nullptr) {
        finish(ctx, kErrorUnknownThread);
        return;
    }
    if (target->state == ThreadState::Dormant || target->state == ThreadState::Dead) {
        finish(ctx, static_cast<std::uint32_t>(target->exit_status));
        return;
    }
    Thread *self = current();
    if (self != nullptr) {
        self->wait_uid = target->uid;
        begin_timeout(*self, ctx.gpr[5]);
    }
    block(ctx, WaitType::ThreadEnd, 0u);
}

void Kernel::sceKernelCreateCallback(Ctx &ctx) {
    // sceKernelCreateCallback(const char *name, SceKernelCallbackFunction func, void *arg)
    // a0 names the callback, a1 is the entry point and a2 the handler argument.
    const std::int32_t uid = new_uid();
    callbacks_[uid] = Callback{ctx.gpr[5], ctx.gpr[6], 0u, ctx.gpr[28], 0, true, false, 0, false};
    finish(ctx, static_cast<std::uint32_t>(uid));
}

void Kernel::sceKernelRegisterCallback(Ctx &ctx) {
    const std::int32_t priority = static_cast<std::int32_t>(ctx.gpr[4]);
    const std::uint32_t entry_ptr = ctx.gpr[5];
    const std::uint32_t common = ctx.gpr[6];
    (void)common; // the handler argument comes from entry_ptr+4; a2 is unused here
    auto &m = rt_.memory();
    const std::uint32_t entry = m.load32(entry_ptr);
    const std::uint32_t arg = m.load32(entry_ptr + 4u);
    const std::uint32_t gp = m.load32(entry_ptr + 8u);
    const std::int32_t uid = new_uid();
    callbacks_[uid] = Callback{entry, arg, 0u, gp, priority, true, false, 0, false};
    finish(ctx, static_cast<std::uint32_t>(uid));
}

// sceKernelRegisterExitCallback(SceUID cbid): the named callback runs only when
// the game exits, never on VBlank.  Without this, the exit handler was swept as
// a plain callback every frame and tore the game down during init.
void Kernel::sceKernelRegisterExitCallback(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    if (auto it = callbacks_.find(uid); it != callbacks_.end()) it->second.exit_only = true;
    finish(ctx, 0u);
}

void Kernel::sceKernelCheckCallback(Ctx &ctx) {
    // Clear running callbacks whose handler threads have finished.
    for (auto &[uid, cb] : callbacks_) {
        if (cb.running != 0 && !threads_.contains(cb.running)) cb.running = 0;
    }
    // Find the highest-priority pending enabled callback.
    std::int32_t best_uid = 0;
    std::int32_t best_priority = 0x7FFFFFFF;
    for (auto &[uid, cb] : callbacks_) {
        if (!cb.enabled || cb.exit_only || !cb.pending || cb.running != 0) continue;
        if (cb.priority < best_priority) {
            best_priority = cb.priority;
            best_uid = uid;
        }
    }
    if (best_uid == 0) {
        finish(ctx, 0u);
        return;
    }
    auto &cb = callbacks_[best_uid];
    cb.pending = false;
    // UMD callbacks take the drive status in a1; refresh it so the handler sees
    // the current state rather than the value captured when it was registered.
    if (cb.umd) cb.arg1 = kUmdDriveStat;
    const std::int32_t handler_uid = start_handler(cb.entry, cb.gp, cb.arg, cb.arg1, nullptr);
    if (handler_uid == 0) {
        cb.pending = true; // re-mark the callback if the handler fails to start.
        finish(ctx, 0u);
        return;
    }
    cb.running = handler_uid;
    finish(ctx, static_cast<std::uint32_t>(handler_uid));
}

void Kernel::scePowerRegisterCallback(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[5]);
    if (auto it = callbacks_.find(uid); it != callbacks_.end()) it->second.pending = true;
    finish(ctx, 0u);
}

void Kernel::sceUmdRegisterUMDCallBack(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    if (auto it = callbacks_.find(uid); it != callbacks_.end()) {
        // The firmware calls the handler as SceUmdCallback(int arg, int stat), so
        // the current drive status has to reach a1 on each dispatch.
        it->second.umd = true;
        it->second.arg1 = kUmdDriveStat;
        it->second.pending = true;
    }
    finish(ctx, 0u);
}

void Kernel::sceKernelGetSystemTimeLow(Ctx &ctx) {
    finish(ctx, static_cast<std::uint32_t>(cheat_freeze_clock_ ? cheat_frozen_us_ : now_us()));
}
void Kernel::sceKernelGetSystemTimeWide(Ctx &ctx) {
    finish64(ctx, cheat_freeze_clock_ ? cheat_frozen_us_ : now_us());
}

void Kernel::sceKernelGetSystemTime(Ctx &ctx) {
    const std::uint64_t now = now_us();
    if (ctx.gpr[4] != 0u) {
        rt_.memory().store32(ctx.gpr[4], static_cast<std::uint32_t>(now));
        rt_.memory().store32(ctx.gpr[4] + 4u, static_cast<std::uint32_t>(now >> 32u));
    }
    finish(ctx, 0u);
}

void Kernel::sysclock_to_usec(std::uint64_t clock, std::uint32_t low_addr, std::uint32_t high_addr) {
    if (low_addr == 0u) {
        if (high_addr != 0u) rt_.memory().store32(high_addr, static_cast<std::uint32_t>(clock));
    } else {
        rt_.memory().store32(low_addr, static_cast<std::uint32_t>(clock / 1000000ull));
        if (high_addr != 0u) rt_.memory().store32(high_addr, static_cast<std::uint32_t>(clock % 1000000ull));
    }
}

void Kernel::sceKernelUSec2SysClock(Ctx &ctx) {
    if (ctx.gpr[5] != 0u) {
        rt_.memory().store32(ctx.gpr[5], ctx.gpr[4]);
        rt_.memory().store32(ctx.gpr[5] + 4u, 0u);
    }
    finish(ctx, 0u);
}

void Kernel::sceKernelUSec2SysClockWide(Ctx &ctx) {
    finish64(ctx, ctx.gpr[4]);
}

void Kernel::sceKernelSysClock2USec(Ctx &ctx) {
    const std::uint64_t clock = ctx.gpr[4] != 0u
        ? (rt_.memory().load32(ctx.gpr[4]) | (static_cast<std::uint64_t>(rt_.memory().load32(ctx.gpr[4] + 4u)) << 32u))
        : 0ull;
    sysclock_to_usec(clock, ctx.gpr[5], ctx.gpr[6]);
    finish(ctx, 0u);
}

void Kernel::sceKernelSysClock2USecWide(Ctx &ctx) {
    const std::uint64_t clock = ctx.gpr[4] | (static_cast<std::uint64_t>(ctx.gpr[5]) << 32u);
    sysclock_to_usec(clock, ctx.gpr[6], ctx.gpr[7]);
    finish(ctx, 0u);
}

void Kernel::sceKernelCreateSema(Ctx &ctx) {
    const std::int32_t uid = new_uid();
    semaphores_[uid] = Semaphore{read_string(ctx.gpr[4], 32), static_cast<std::int32_t>(ctx.gpr[6]),
                                 static_cast<std::int32_t>(ctx.gpr[7])};
    finish(ctx, static_cast<std::uint32_t>(uid));
}

void Kernel::sceKernelDeleteSema(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    if (semaphores_.erase(uid) == 0u) {
        finish(ctx, kErrorUnknownSema);
        return;
    }
    for (auto &[tid, t] : threads_) {
        (void)tid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::Sema && t.wait_uid == uid)
            wake(t, kErrorWaitDelete);
    }
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

bool Kernel::try_satisfy_sema(Thread &t) {
    auto it = semaphores_.find(t.wait_uid);
    if (it == semaphores_.end() || it->second.count < static_cast<std::int32_t>(t.wait_count)) return false;
    it->second.count -= static_cast<std::int32_t>(t.wait_count);
    return true;
}

void Kernel::sceKernelSignalSema(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    auto it = semaphores_.find(uid);
    if (it == semaphores_.end()) {
        finish(ctx, kErrorUnknownSema);
        return;
    }
    const std::int32_t signal = static_cast<std::int32_t>(ctx.gpr[5]);
    if (it->second.max > 0 && it->second.count + signal > it->second.max) {
        finish(ctx, kErrorSemaOverflow);
        return;
    }
    it->second.count += signal;
    // Wake waiters in priority order while the count satisfies them.
    std::vector<Thread *> waiters;
    for (auto &[tid, t] : threads_) {
        (void)tid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::Sema && t.wait_uid == uid) waiters.push_back(&t);
    }
    std::sort(waiters.begin(), waiters.end(), [](const Thread *a, const Thread *b) { return a->priority < b->priority; });
    for (Thread *t : waiters)
        if (try_satisfy_sema(*t)) wake(*t, 0u);
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

void Kernel::sceKernelWaitSema(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    auto it = semaphores_.find(uid);
    if (it == semaphores_.end()) {
        finish(ctx, kErrorUnknownSema);
        return;
    }
    const std::int32_t need = static_cast<std::int32_t>(ctx.gpr[5]);
    if (it->second.count >= need) {
        it->second.count -= need;
        finish(ctx, 0u);
        return;
    }
    Thread *self = current();
    if (self != nullptr) {
        self->wait_uid = uid;
        self->wait_count = static_cast<std::uint32_t>(need);
        begin_timeout(*self, ctx.gpr[6]);
    }
    block(ctx, WaitType::Sema, 0u);
}

void Kernel::sceKernelPollSema(Ctx &ctx) {
    auto it = semaphores_.find(static_cast<std::int32_t>(ctx.gpr[4]));
    if (it == semaphores_.end()) {
        finish(ctx, kErrorUnknownSema);
        return;
    }
    const std::int32_t need = static_cast<std::int32_t>(ctx.gpr[5]);
    if (it->second.count >= need) {
        it->second.count -= need;
        finish(ctx, 0u);
    } else {
        finish(ctx, kErrorSemaZero);
    }
}

// ---------------------------------------------------------------------------
// Mutexes: owned by one thread at a time, optionally recursive (attr 0x200).

void Kernel::sceKernelCreateMutex(Ctx &ctx) {
    const std::int32_t uid = new_uid();
    Mutex mutex{read_string(ctx.gpr[4], 32), ctx.gpr[5], static_cast<std::int32_t>(ctx.gpr[6]), 0};
    if (mutex.count > 0) mutex.owner = current_uid_;
    mutexes_[uid] = std::move(mutex);
    finish(ctx, static_cast<std::uint32_t>(uid));
}

void Kernel::sceKernelDeleteMutex(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    if (mutexes_.erase(uid) == 0u) {
        finish(ctx, kErrorUnknownMutex);
        return;
    }
    for (auto &[tid, t] : threads_) {
        (void)tid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::Mutex && t.wait_uid == uid) wake(t, kErrorWaitDelete);
    }
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

// Shared by Lock and TryLock: 0 if the lock was taken, an error, or 1 if the caller has to wait.
static std::uint32_t take_mutex(Mutex &mutex, std::int32_t self, std::int32_t count) {
    if (count <= 0) return kErrorIllegalCount;
    if (mutex.count == 0) {
        mutex.owner = self;
        mutex.count = count;
        return 0u;
    }
    if (mutex.owner == self) {
        if ((mutex.attr & 0x200u) == 0u) return kErrorMutexRecursive;
        mutex.count += count;
        return 0u;
    }
    return 1u;
}

void Kernel::sceKernelLockMutex(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    auto it = mutexes_.find(uid);
    if (it == mutexes_.end()) {
        finish(ctx, kErrorUnknownMutex);
        return;
    }
    const std::int32_t count = static_cast<std::int32_t>(ctx.gpr[5]);
    const std::uint32_t result = take_mutex(it->second, current_uid_, count);
    if (result != 1u) {
        finish(ctx, result);
        return;
    }
    Thread *self = current();
    if (self != nullptr) {
        self->wait_uid = uid;
        self->wait_count = static_cast<std::uint32_t>(count);
        begin_timeout(*self, ctx.gpr[6]);
    }
    block(ctx, WaitType::Mutex, 0u);
}

void Kernel::sceKernelTryLockMutex(Ctx &ctx) {
    auto it = mutexes_.find(static_cast<std::int32_t>(ctx.gpr[4]));
    if (it == mutexes_.end()) {
        finish(ctx, kErrorUnknownMutex);
        return;
    }
    const std::uint32_t result = take_mutex(it->second, current_uid_, static_cast<std::int32_t>(ctx.gpr[5]));
    finish(ctx, result == 1u ? kErrorMutexLocked : result);
}

void Kernel::sceKernelUnlockMutex(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    auto it = mutexes_.find(uid);
    if (it == mutexes_.end()) {
        finish(ctx, kErrorUnknownMutex);
        return;
    }
    Mutex &mutex = it->second;
    const std::int32_t count = static_cast<std::int32_t>(ctx.gpr[5]);
    if (count <= 0) {
        finish(ctx, kErrorIllegalCount);
        return;
    }
    if (mutex.count == 0 || mutex.owner != current_uid_ || count > mutex.count) {
        finish(ctx, kErrorMutexUnlockUnderflow);
        return;
    }
    mutex.count -= count;
    if (mutex.count == 0) {
        mutex.owner = 0;
        // Hand the mutex to the waiter that comes first (by priority if attr 0x100, else in order).
        Thread *next = nullptr;
        for (auto &[tid, t] : threads_) {
            (void)tid;
            if (t.state != ThreadState::Waiting || t.wait != WaitType::Mutex || t.wait_uid != uid) continue;
            if (next == nullptr || ((mutex.attr & 0x100u) != 0u && t.priority < next->priority)) next = &t;
        }
        if (next != nullptr) {
            mutex.owner = next->uid;
            mutex.count = static_cast<std::int32_t>(next->wait_count);
            wake(*next, 0u);
        }
    }
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

// ---------------------------------------------------------------------------
// Message boxes

void Kernel::sceKernelCreateMbx(Ctx &ctx) {
    const std::int32_t uid = new_uid();
    mailboxes_[uid] = Mailbox{read_string(ctx.gpr[4], 32), ctx.gpr[5], {}};
    finish(ctx, static_cast<std::uint32_t>(uid));
}

void Kernel::sceKernelDeleteMbx(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    if (mailboxes_.erase(uid) == 0u) {
        finish(ctx, kErrorUnknownMbx);
        return;
    }
    for (auto &[tid, t] : threads_) {
        (void)tid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::Mbx && t.wait_uid == uid) wake(t, kErrorWaitDelete);
    }
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

void Kernel::sceKernelSendMbx(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    auto it = mailboxes_.find(uid);
    if (it == mailboxes_.end()) {
        finish(ctx, kErrorUnknownMbx);
        return;
    }
    const std::uint32_t message = ctx.gpr[5];
    for (auto &[tid, t] : threads_) {
        (void)tid;
        if (t.state != ThreadState::Waiting || t.wait != WaitType::Mbx || t.wait_uid != uid) continue;
        if (t.wait_out_address != 0u) rt_.memory().store32(t.wait_out_address, message);
        wake(t, 0u);
        finish(ctx, 0u);
        maybe_preempt(ctx);
        return;
    }
    auto &queue = it->second.messages;
    if ((it->second.attr & 0x400u) != 0u) {
        // Priority-ordered box: the packet's priority byte follows its next pointer.
        const std::uint8_t priority = rt_.memory().load8(message + 4u);
        auto pos = std::find_if(queue.begin(), queue.end(),
                                [&](std::uint32_t m) { return rt_.memory().load8(m + 4u) > priority; });
        queue.insert(pos, message);
    } else {
        queue.push_back(message);
    }
    finish(ctx, 0u);
}

void Kernel::sceKernelReceiveMbx(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    auto it = mailboxes_.find(uid);
    if (it == mailboxes_.end()) {
        finish(ctx, kErrorUnknownMbx);
        return;
    }
    if (!it->second.messages.empty()) {
        if (ctx.gpr[5] != 0u) rt_.memory().store32(ctx.gpr[5], it->second.messages.front());
        it->second.messages.pop_front();
        finish(ctx, 0u);
        return;
    }
    Thread *self = current();
    if (self != nullptr) {
        self->wait_uid = uid;
        self->wait_out_address = ctx.gpr[5];
        begin_timeout(*self, ctx.gpr[6]);
    }
    block(ctx, WaitType::Mbx, 0u);
}

void Kernel::sceKernelPollMbx(Ctx &ctx) {
    auto it = mailboxes_.find(static_cast<std::int32_t>(ctx.gpr[4]));
    if (it == mailboxes_.end()) {
        finish(ctx, kErrorUnknownMbx);
        return;
    }
    if (it->second.messages.empty()) {
        finish(ctx, kErrorMbxNoMessage);
        return;
    }
    if (ctx.gpr[5] != 0u) rt_.memory().store32(ctx.gpr[5], it->second.messages.front());
    it->second.messages.pop_front();
    finish(ctx, 0u);
}

// ---------------------------------------------------------------------------
// Sub-interrupt handlers.  Vblank handlers run once per frame, each on a
// short-lived thread that outranks every game thread.

void Kernel::sceKernelRegisterSubIntrHandler(Ctx &ctx) {
    sub_interrupts_[{ctx.gpr[4], ctx.gpr[5]}] = SubInterrupt{ctx.gpr[6], ctx.gpr[7], ctx.gpr[28], false, 0};
    finish(ctx, 0u);
}

void Kernel::sceKernelReleaseSubIntrHandler(Ctx &ctx) {
    sub_interrupts_.erase({ctx.gpr[4], ctx.gpr[5]});
    finish(ctx, 0u);
}

void Kernel::sceKernelEnableSubIntr(Ctx &ctx) {
    auto it = sub_interrupts_.find({ctx.gpr[4], ctx.gpr[5]});
    if (it != sub_interrupts_.end()) it->second.enabled = true;
    finish(ctx, 0u);
}

void Kernel::sceKernelDisableSubIntr(Ctx &ctx) {
    auto it = sub_interrupts_.find({ctx.gpr[4], ctx.gpr[5]});
    if (it != sub_interrupts_.end()) it->second.enabled = false;
    finish(ctx, 0u);
}

void Kernel::run_interrupts(std::uint32_t interrupt) {
    for (auto &[key, handler] : sub_interrupts_) {
        if (key.first != interrupt || !handler.enabled || handler.handler == 0u) continue;
        if (handler.running != 0 && threads_.contains(handler.running)) continue; // still busy with the last one
        const std::int32_t uid = start_handler(handler.handler, handler.gp, key.second, handler.arg, nullptr);
        if (uid == 0) return;
        handler.running = uid;
    }
}

std::int32_t Kernel::start_handler(std::uint32_t entry, std::uint32_t gp, std::uint32_t a0, std::uint32_t a1,
                                   std::function<std::uint32_t(std::uint32_t)> done) {
    Thread t;
    t.uid = new_uid();
    t.name = "pspweb_interrupt";
    t.entry = entry;
    t.priority = 1;
    t.stack_size = 0x4000u;
    t.stack_block = allocate("stack:interrupt", 1u, t.stack_size, 0u);
    if (t.stack_block < 0) {
        t.stack_size = 0x1000u;
        t.stack_block = allocate("stack:interrupt", 1u, t.stack_size, 0u);
    }
    if (t.stack_block >= 0) {
        t.stack_top = blocks_.at(t.stack_block).address + t.stack_size;
    } else {
        t.stack_size = 0x3C00u;
        t.stack_top = kUserPartitionStart + 0x4000u;
    }
    t.gp = gp;
    const std::int32_t uid = t.uid;
    auto &stored = threads_[uid] = std::move(t);
    start_thread(stored, 0u, {});
    stored.ctx.gpr[4] = a0;
    stored.ctx.gpr[5] = a1;
    make_ready(stored, true);
    guest_calls_[uid] = GuestCall{0, std::move(done)}; // removed again when it returns
    return uid;
}

void Kernel::set_alarm(Ctx &ctx, std::uint64_t delay_us) {
    const std::int32_t uid = new_uid();
    alarms_[uid] = Alarm{now_us() + delay_us, ctx.gpr[5], ctx.gpr[6], ctx.gpr[28], 0};
    finish(ctx, static_cast<std::uint32_t>(uid));
}

void Kernel::sceKernelSetAlarm(Ctx &ctx) { set_alarm(ctx, ctx.gpr[4]); }

void Kernel::sceKernelSetSysClockAlarm(Ctx &ctx) {
    auto &m = rt_.memory();
    set_alarm(ctx, m.load32(ctx.gpr[4]) | static_cast<std::uint64_t>(m.load32(ctx.gpr[4] + 4u)) << 32u);
}

void Kernel::sceKernelCancelAlarm(Ctx &ctx) {
    finish(ctx, alarms_.erase(static_cast<std::int32_t>(ctx.gpr[4])) != 0u ? 0u : kErrorUnknownAlarm);
}

void Kernel::run_alarms() {
    const std::uint64_t now = now_us();
    for (auto &[uid, alarm] : alarms_) {
        if (alarm.running != 0 || now < alarm.at) continue;
        const std::int32_t id = uid;
        alarm.running = start_handler(alarm.handler, alarm.gp, alarm.common, 0u, [this, id](std::uint32_t next) {
            const auto it = alarms_.find(id);
            if (it == alarms_.end()) return 0u;
            if (next == 0u) {
                alarms_.erase(it);
            } else {
                it->second.at = now_us() + next;
                it->second.running = 0;
            }
            return 0u;
        });
        if (alarm.running == 0) return;
    }
}

void Kernel::sceKernelCreateEventFlag(Ctx &ctx) {
    const std::int32_t uid = new_uid();
    event_flags_[uid] = EventFlag{read_string(ctx.gpr[4], 32), ctx.gpr[5], ctx.gpr[6]};
    finish(ctx, static_cast<std::uint32_t>(uid));
}

void Kernel::sceKernelDeleteEventFlag(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    if (event_flags_.erase(uid) == 0u) {
        finish(ctx, kErrorUnknownEventFlag);
        return;
    }
    for (auto &[tid, t] : threads_) {
        (void)tid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::EventFlag && t.wait_uid == uid)
            wake(t, kErrorWaitDelete);
    }
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

bool Kernel::try_satisfy_event(Thread &t) {
    auto it = event_flags_.find(t.wait_uid);
    if (it == event_flags_.end()) return false;
    std::uint32_t &pattern = it->second.pattern;
    const std::uint32_t bits = t.wait_count;
    const bool match = (t.wait_mode & kEventWaitOr) != 0u ? (pattern & bits) != 0u : (pattern & bits) == bits;
    if (!match) return false;
    if (t.wait_out_address != 0u) rt_.memory().store32(t.wait_out_address, pattern);
    if ((t.wait_mode & kEventWaitClearAll) != 0u) pattern = 0u;
    else if ((t.wait_mode & kEventWaitClear) != 0u) pattern &= ~bits;
    return true;
}

void Kernel::sceKernelSetEventFlag(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    auto it = event_flags_.find(uid);
    if (it == event_flags_.end()) {
        finish(ctx, kErrorUnknownEventFlag);
        return;
    }
    it->second.pattern |= ctx.gpr[5];
    for (auto &[tid, t] : threads_) {
        (void)tid;
        if (t.state == ThreadState::Waiting && t.wait == WaitType::EventFlag && t.wait_uid == uid &&
            try_satisfy_event(t))
            wake(t, 0u);
    }
    finish(ctx, 0u);
    maybe_preempt(ctx);
}

void Kernel::sceKernelClearEventFlag(Ctx &ctx) {
    auto it = event_flags_.find(static_cast<std::int32_t>(ctx.gpr[4]));
    if (it == event_flags_.end()) {
        finish(ctx, kErrorUnknownEventFlag);
        return;
    }
    it->second.pattern &= ctx.gpr[5];
    finish(ctx, 0u);
}

void Kernel::sceKernelWaitEventFlag(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    if (!event_flags_.contains(uid)) {
        finish(ctx, kErrorUnknownEventFlag);
        return;
    }
    Thread *self = current();
    if (self == nullptr) {
        finish(ctx, 0u);
        return;
    }
    self->wait_uid = uid;
    self->wait_count = ctx.gpr[5];
    self->wait_mode = ctx.gpr[6];
    self->wait_out_address = ctx.gpr[7];
    if (try_satisfy_event(*self)) {
        finish(ctx, 0u);
        return;
    }
    begin_timeout(*self, ctx.gpr[8]);
    block(ctx, WaitType::EventFlag, 0u);
}

void Kernel::sceKernelPollEventFlag(Ctx &ctx) {
    const std::int32_t uid = static_cast<std::int32_t>(ctx.gpr[4]);
    auto it = event_flags_.find(uid);
    if (it == event_flags_.end()) {
        finish(ctx, kErrorUnknownEventFlag);
        return;
    }
    Thread probe;
    probe.wait_uid = uid;
    probe.wait_count = ctx.gpr[5];
    probe.wait_mode = ctx.gpr[6];
    probe.wait_out_address = ctx.gpr[7];
    if (try_satisfy_event(probe)) {
        finish(ctx, 0u);
        return;
    }
    if (ctx.gpr[7] != 0u) rt_.memory().store32(ctx.gpr[7], it->second.pattern);
    finish(ctx, kErrorEventFlagCondition);
}

void Kernel::sceKernelRotateThreadReadyQueue(Ctx &ctx) {
    finish(ctx, 0u);
    Thread *self = current();
    if (self == nullptr) return;
    self->ctx = ctx;
    make_ready(*self);
    reschedule(ctx);
}

// ---------------------------------------------------------------------------
// SysMemUserForUser

void Kernel::sceKernelMaxFreeMemSize(Ctx &ctx) { finish(ctx, largest_free()); }
void Kernel::sceKernelTotalFreeMemSize(Ctx &ctx) { finish(ctx, total_free()); }

void Kernel::sceKernelAllocPartitionMemory(Ctx &ctx) {
    const std::int32_t uid = allocate(read_string(ctx.gpr[5], 32), ctx.gpr[6], ctx.gpr[7], ctx.gpr[8]);
    finish(ctx, uid < 0 ? kErrorNoMemory : static_cast<std::uint32_t>(uid));
}

void Kernel::sceKernelFreePartitionMemory(Ctx &ctx) {
    finish(ctx, blocks_.erase(static_cast<std::int32_t>(ctx.gpr[4])) != 0u ? 0u : kErrorUnknownUid);
}

void Kernel::sceKernelGetBlockHeadAddr(Ctx &ctx) {
    const auto it = blocks_.find(static_cast<std::int32_t>(ctx.gpr[4]));
    finish(ctx, it != blocks_.end() ? it->second.address : kErrorUnknownUid);
}

void Kernel::sceKernelDevkitVersion(Ctx &ctx) { finish(ctx, 0x05000010u); }

void Kernel::sceKernelPrintf(Ctx &ctx) {
    std::cout << "[guest] " << read_string(ctx.gpr[4], 512) << "\n";
    finish(ctx, 0u);
}

// ---------------------------------------------------------------------------
// LoadExecForUser / ModuleMgrForUser / StdioForUser

// The exit callback registered via sceKernelRegisterExitCallback is only ever
// run from here.  It performs the game's own thread/semaphore teardown.
bool Kernel::run_exit_callback() {
    for (auto &[uid, cb] : callbacks_) {
        if (!cb.exit_only || !cb.enabled || cb.entry == 0u) continue;
        const std::int32_t handler_uid = start_handler(cb.entry, cb.gp, cb.arg, 0u, nullptr);
        if (handler_uid == 0) return false;
        cb.running = handler_uid;
        cb.pending = false;
        // Drain the handler to completion; it runs at priority 1 (higher than
        // the caller) so it gets scheduled immediately.
        const auto deadline = Clock::now() + std::chrono::milliseconds(2000);
        while (!halted_ && Clock::now() < deadline) {
            if (!threads_.contains(handler_uid)) break;
            if (Thread *next = pick_ready()) {
                load_thread(*next);
            } else {
                const std::uint64_t wake_at = earliest_timed_wake();
                if (wake_at != 0u && wake_at > now_us()) warp_us_ += wake_at - now_us();
            }
            rt_.run(rt_.cpu().pc, std::numeric_limits<std::uint64_t>::max());
            const std::string &r = rt_.stop_reason();
            if (r == "exit") break;
        }
        return true;
    }
    return false;
}

void Kernel::sceKernelExitGame(Ctx &ctx) {
    // A title calling this during boot has already decided it cannot carry on
    // (a missing utility, a checked failure) and the log does not say why: the
    // call is usually the last thing the guest does before it goes quiet, and
    // every thread then parks in a delay wait while the page keeps rendering
    // nothing, so it reads as a hang.  Report it loudly with enough state to
    // tell "the game asked to quit" apart from "the guest wedged", name the
    // caller, and refuse to schedule another frame so the page shows it stopped.
    const Thread *self = current();
    std::cerr << "[kernel] *** sceKernelExitGame: the guest asked to exit at vcount " << display_.vcount
              << ", frame " << display_.flips << " flips, from thread "
              << (self != nullptr ? self->name : std::string("<none>"))
              << " (" << current_uid_ << ") pc=0x" << std::hex << rt_.cpu().pc << " ra=0x" << ctx.gpr[31]
              << std::dec << " ***\n";
    dump_diagnosis("exitgame");
    finish(ctx, 0u);
    // Give the exit callback a chance to tear the game down cleanly.
    run_exit_callback();
    halted_ = true;
    halt_reason_ = "exit";
    rt_.stop("exit");
}


void Kernel::sceKernelStdin(Ctx &ctx) { finish(ctx, 0u); }
void Kernel::sceKernelStdout(Ctx &ctx) { finish(ctx, 1u); }
void Kernel::sceKernelStderr(Ctx &ctx) { finish(ctx, 2u); }

// ---------------------------------------------------------------------------
// sceDisplay / sceGe_user

void Kernel::sceDisplaySetMode(Ctx &ctx) { finish(ctx, 0u); }

// Some games (God of War among them) flip without waiting for vblank and would
// render several frames per displayed one.  Like PPSSPP, a second buffer change
// within one vblank holds the calling thread until the next vblank.
void Kernel::sceDisplaySetFrameBuf(Ctx &ctx) {
    ++display_.flips;
    const bool new_buffer = ctx.gpr[4] != 0u && display_.framebuffer != 0u && ctx.gpr[4] != display_.framebuffer;
    display_.framebuffer = ctx.gpr[4];
    if (ctx.gpr[5] != 0u) display_.stride = ctx.gpr[5];
    display_.format = ctx.gpr[6];
    if (new_buffer && throttle_flips_) {
        if (display_.flip_vcount == display_.vcount) {
            display_.flip_vcount = display_.vcount + 1u;
            block(ctx, WaitType::Vblank, 0u);
            return;
        }
        display_.flip_vcount = display_.vcount;
    }
    finish(ctx, 0u);
}

void Kernel::sceDisplayGetFrameBuf(Ctx &ctx) {
    if (ctx.gpr[4] != 0u) rt_.memory().store32(ctx.gpr[4], display_.framebuffer);
    if (ctx.gpr[5] != 0u) rt_.memory().store32(ctx.gpr[5], display_.stride);
    if (ctx.gpr[6] != 0u) rt_.memory().store32(ctx.gpr[6], display_.format);
    finish(ctx, 0u);
}

void Kernel::sceDisplayWaitVblankStart(Ctx &ctx) { block(ctx, WaitType::Vblank, 0u); }
void Kernel::sceDisplayGetVcount(Ctx &ctx) { finish(ctx, display_.vcount); }
void Kernel::sceGeEdramGetAddr(Ctx &ctx) { finish(ctx, kVramAddress); }
void Kernel::sceGeEdramGetSize(Ctx &ctx) { finish(ctx, kVramSize); }

// Display lists go to the GE worker and run while the guest carries on, as on
// the PSP; a stalled list resumes from where it stopped when the stall address
// moves.  The sync calls wait (mode 0) or report the state (mode 1).
void Kernel::sceGeListEnQueue(Ctx &ctx) {
    const auto callback = static_cast<std::int32_t>(ctx.gpr[6]);
    finish(ctx, ge_worker_->enqueue(ctx.gpr[4], ctx.gpr[5], ge_callbacks_.contains(callback) ? callback : -1));
}

void Kernel::sceGeSetCallback(Ctx &ctx) {
    auto &m = rt_.memory();
    const std::uint32_t data = ctx.gpr[4];
    for (std::int32_t id = 0; id < 16; ++id) {
        if (ge_callbacks_.contains(id)) continue;
        ge_callbacks_[id] = GeCallback{m.load32(data), m.load32(data + 4u), m.load32(data + 8u), m.load32(data + 12u), ctx.gpr[28]};
        finish(ctx, static_cast<std::uint32_t>(id));
        return;
    }
    finish(ctx, kErrorNoMemory);
}

void Kernel::sceGeUnsetCallback(Ctx &ctx) {
    ge_callbacks_.erase(static_cast<std::int32_t>(ctx.gpr[4]));
    finish(ctx, 0u);
}

void Kernel::run_ge_callbacks() {
    if (ge_callback_running_ != 0 && threads_.contains(ge_callback_running_)) return;
    ge_callback_running_ = 0;
    while (true) {
        GeEvent event{};
        {
            const std::lock_guard<std::mutex> lock(ge_events_mutex_);
            if (ge_events_.empty()) {
                ge_event_pending_.store(false, std::memory_order_relaxed);
                return;
            }
            event = ge_events_.front();
            ge_events_.pop_front();
            ge_event_pending_.store(!ge_events_.empty(), std::memory_order_relaxed);
        }
        const auto it = ge_callbacks_.find(event.callback);
        if (it == ge_callbacks_.end()) continue;
        const GeCallback &callback = it->second;
        const std::uint32_t entry = event.finish ? callback.finish : callback.signal;
        if (entry == 0u) continue;
        const std::int32_t uid = start_handler(
            entry, callback.gp, event.value, event.finish ? callback.finish_arg : callback.signal_arg,
            [this](std::uint32_t status) {
                ge_callback_running_ = 0;
                run_ge_callbacks();
                return status;
            });
        if (uid != 0) {
            ge_callback_running_ = uid;
            return;
        }
    }
}

void Kernel::sceGeListUpdateStallAddr(Ctx &ctx) {
    ge_worker_->update_stall(ctx.gpr[4], ctx.gpr[5]);
    finish(ctx, 0u);
}

namespace {
constexpr std::uint32_t kGeListCompleted = 0u, kGeListDrawing = 2u;
}

void Kernel::sceGeListSync(Ctx &ctx) {
    const std::uint32_t id = ctx.gpr[4];
    if (ge_worker_->done(id == 0u ? 1u : id)) {
        finish(ctx, kGeListCompleted);
    } else if (ctx.gpr[5] == 1u) {
        finish(ctx, kGeListDrawing);
    } else {
        current()->wait_count = id == 0u ? 1u : id;
        block(ctx, WaitType::Ge, kGeListCompleted);
    }
}

void Kernel::sceGeDrawSync(Ctx &ctx) {
    if (ge_worker_->done(0u)) {
        finish(ctx, kGeListCompleted);
    } else if (ctx.gpr[4] == 1u) {
        finish(ctx, kGeListDrawing);
    } else {
        current()->wait_count = 0u;
        block(ctx, WaitType::Ge, kGeListCompleted);
    }
}

void Kernel::sceGeGetCmd(Ctx &ctx) { finish(ctx, 0u); }

// The context is saved and restored on the GE thread, in order with the queued lists.
void Kernel::sceGeSaveContext(Ctx &ctx) {
    std::vector<std::uint32_t> words;
    ge_worker_->call([&] { words = ge_->save_context(); });
    const std::uint32_t address = ctx.gpr[4];
    for (std::uint32_t i = 0; i < 512u; ++i)
        rt_.memory().store32(address + i * 4u, i < words.size() ? words[i] : 0u);
    finish(ctx, 0u);
}

void Kernel::sceGeRestoreContext(Ctx &ctx) {
    std::vector<std::uint32_t> words;
    for (std::uint32_t i = 0; i < 512u; ++i) {
        const std::uint32_t op = rt_.memory().load32(ctx.gpr[4] + i * 4u);
        if (op == 0u) break;
        words.push_back(op);
    }
    ge_worker_->post([ge = ge_.get(), words = std::move(words)] { ge->restore_context(words); });
    finish(ctx, 0u);
}

void Kernel::read_framebuffer(std::uint8_t *rgba) const {
    constexpr std::uint32_t width = 480u, height = 272u;
    if (display_.framebuffer == 0u) {
        for (std::uint32_t i = 0; i < width * height; ++i) {
            rgba[i * 4u + 0u] = rgba[i * 4u + 1u] = rgba[i * 4u + 2u] = 0u;
            rgba[i * 4u + 3u] = 255u;
        }
        return;
    }
    const std::uint32_t bpp = display_.format == 3u ? 4u : 2u;
    for (std::uint32_t y = 0; y < height; ++y) {
        const std::uint8_t *row = rt_.memory().raw_pointer(
            display_.framebuffer + y * display_.stride * bpp, width * bpp);
        std::uint8_t *out = rgba + y * width * 4u;
        for (std::uint32_t x = 0; x < width; ++x, out += 4u) {
            if (row == nullptr) {
                out[0] = out[1] = out[2] = 0u;
            } else if (bpp == 4u) {
                out[0] = row[x * 4u + 0u];
                out[1] = row[x * 4u + 1u];
                out[2] = row[x * 4u + 2u];
            } else {
                const std::uint32_t v = static_cast<std::uint32_t>(row[x * 2u]) |
                                        (static_cast<std::uint32_t>(row[x * 2u + 1u]) << 8u);
                if (display_.format == 0u) { // 5650
                    out[0] = static_cast<std::uint8_t>(((v >> 0u) & 31u) * 255u / 31u);
                    out[1] = static_cast<std::uint8_t>(((v >> 5u) & 63u) * 255u / 63u);
                    out[2] = static_cast<std::uint8_t>(((v >> 11u) & 31u) * 255u / 31u);
                } else if (display_.format == 1u) { // 5551
                    out[0] = static_cast<std::uint8_t>(((v >> 0u) & 31u) * 255u / 31u);
                    out[1] = static_cast<std::uint8_t>(((v >> 5u) & 31u) * 255u / 31u);
                    out[2] = static_cast<std::uint8_t>(((v >> 10u) & 31u) * 255u / 31u);
                } else { // 4444
                    out[0] = static_cast<std::uint8_t>(((v >> 0u) & 15u) * 17u);
                    out[1] = static_cast<std::uint8_t>(((v >> 4u) & 15u) * 17u);
                    out[2] = static_cast<std::uint8_t>(((v >> 8u) & 15u) * 17u);
                }
            }
            out[3] = 255u;
        }
    }
}

// ---------------------------------------------------------------------------
// UtilsForUser / Kernel_Library

void Kernel::sceKernelLibcTime(Ctx &ctx) {
    const auto now = static_cast<std::uint32_t>(std::time(nullptr));
    if (ctx.gpr[4] != 0u) rt_.memory().store32(ctx.gpr[4], now);
    finish(ctx, now);
}

void Kernel::sceKernelLibcGettimeofday(Ctx &ctx) {
    const std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr)) * 1000000u + now_us() % 1000000u;
    if (ctx.gpr[4] != 0u) {
        rt_.memory().store32(ctx.gpr[4], static_cast<std::uint32_t>(now / 1000000u));
        rt_.memory().store32(ctx.gpr[4] + 4u, static_cast<std::uint32_t>(now % 1000000u));
    }
    finish(ctx, 0u);
}

void Kernel::sceKernelMemcpy(Ctx &ctx) {
    const std::uint32_t dst = ctx.gpr[4], src = ctx.gpr[5], size = ctx.gpr[6];
    std::uint8_t *to = rt_.memory().raw_pointer(dst, size);
    const std::uint8_t *from = rt_.memory().raw_pointer(src, size);
    if (to != nullptr && from != nullptr) {
        std::memmove(to, from, size);
    } else {
        std::vector<std::uint8_t> bytes(size);
        for (std::uint32_t i = 0; i < size; ++i) bytes[i] = rt_.memory().load8(src + i);
        for (std::uint32_t i = 0; i < size; ++i) rt_.memory().store8(dst + i, bytes[i]);
    }
    finish(ctx, dst);
}

void Kernel::sceKernelMemset(Ctx &ctx) {
    const std::uint32_t dst = ctx.gpr[4], size = ctx.gpr[6];
    const auto value = static_cast<std::uint8_t>(ctx.gpr[5]);
    if (std::uint8_t *to = rt_.memory().raw_pointer(dst, size); to != nullptr) {
        std::memset(to, value, size);
    } else {
        for (std::uint32_t i = 0; i < size; ++i) rt_.memory().store8(dst + i, value);
    }
    finish(ctx, dst);
}

void Kernel::sceKernelCpuSuspendIntr(Ctx &ctx) { finish(ctx, 1u); }
void Kernel::return_zero(Ctx &ctx) { finish(ctx, 0u); }

// ---------------------------------------------------------------------------
// Cheats (see cheats.hpp and docs/cheats.md).

void Kernel::install_cheats() {
    cheats_.set_memory(&rt_.memory());
    scanner_.set_memory(&rt_.memory());
    // freeze_clock holds the guest's timestamp at the current frame, so countdowns
    // and timers stand still.  It is a *state*, not a one-shot: frame() derives
    // cheat_freeze_clock_ from whether any enabled cheat uses the action, and
    // captures the base value the first frame it is armed.  The callback itself
    // only records the request; it has no effect on its own.
    cheats_.register_action("freeze_clock", [this](const CheatEntry &) { cheat_freeze_clock_ = true; });
}

CheatLoadResult Kernel::load_cheats(const std::string &text) {
    CheatLoadResult parsed = parse_cheats(text);
    // A cheat that names an unknown host action can never do anything; report it
    // rather than let it sit in the list looking active.
    for (auto &cheat : parsed.cheats) {
        for (auto &entry : cheat.entries) {
            if (!entry.action.empty() && !cheats_.has_action(entry.action))
                parsed.errors.push_back("cheat " + cheat.id + ": unknown host action '" + entry.action + "'");
        }
    }
    cheats_.set_memory(&rt_.memory());
    cheats_.set_cheats(std::move(parsed));
    // Return what the engine now holds (set_cheats preserves existing toggles).
    return CheatLoadResult{cheats_.cheats(), cheats_.errors()};
}

} // namespace pspweb
