#pragma once

// Minimal PSP kernel for the web profile: cooperative threads, wait objects,
// the user memory partition, file I/O and the display registers.  Anything a
// title imports that is not implemented here gets a logging stub returning 0,
// so bring-up shows which services a game actually needs.

#include "ge.hpp"
#include "cheats.hpp"
#include "memory_scan.hpp"
#include "ge_worker.hpp"
#include "generated_modules.hpp"
#include "webfs.hpp"

#include "psprecomp/elf32.hpp"
#include "psprecomp/runtime.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace pspweb {

// Host trampoline a guest thread returns into when its entry function ends.
// Placed in the 16 KiB gap below the module load base so the runtime's direct
// PC table does not grow to cover the kernel partition.
inline constexpr std::uint32_t kThreadReturnAddress = 0x08800100u;
inline constexpr std::uint32_t kUserPartitionStart = 0x08800000u;
inline constexpr std::uint32_t kUserPartitionEnd = 0x0A000000u;
inline constexpr std::uint32_t kVramAddress = 0x04000000u;
inline constexpr std::uint32_t kVramSize = 0x00200000u;

// UMD drive status bits reported to guests.  The disc served by the webfs is
// always mounted and readable, so every query reports present|ready|readable
// (0x02|0x10|0x20).  Titles wait on UMD_READY (0x20) before streaming data.
inline constexpr std::uint32_t kUmdDriveStat = 0x32u;

enum class ThreadState { Dormant, Ready, Running, Waiting, Dead };
enum class WaitType { None, Sleep, Delay, Vblank, ThreadEnd, Sema, EventFlag, Fpl, Io, Callback, Ge, Mutex, Mbx, CtrlRead };

// PSP pad button bits (SceCtrlData::Buttons).
namespace pad {
inline constexpr std::uint32_t kSelect = 0x0001u, kStart = 0x0008u, kUp = 0x0010u, kRight = 0x0020u,
    kDown = 0x0040u, kLeft = 0x0080u, kL = 0x0100u, kR = 0x0200u, kTriangle = 0x1000u,
    kCircle = 0x2000u, kCross = 0x4000u, kSquare = 0x8000u;
}

struct Thread {
    std::int32_t uid{};
    std::string name;
    std::uint32_t entry{};
    std::int32_t priority{};
    std::uint32_t attr{};
    std::uint32_t stack_size{};
    std::uint32_t stack_top{};
    std::int32_t stack_block{-1};
    std::uint32_t gp{};
    ThreadState state{ThreadState::Dormant};
    WaitType wait{WaitType::None};
    std::int32_t wait_uid{};
    std::uint32_t wait_count{};
    std::uint32_t wait_mode{};
    std::uint32_t wait_out_address{};
    std::uint32_t timeout_address{};
    std::uint64_t wake_time_us{};
    std::uint32_t wakeup_count{};
    std::int32_t exit_status{};
    std::uint64_t ready_sequence{};
    psprecomp::AllegrexContext ctx{};
};

struct Semaphore {
    std::string name;
    std::int32_t count{};
    std::int32_t max{};
};

struct EventFlag {
    std::string name;
    std::uint32_t attr{};
    std::uint32_t pattern{};
};

struct MemoryBlock {
    std::string name;
    std::uint32_t address{};
    std::uint32_t size{};
};

struct OpenFile {
    std::FILE *file{};          // native host file
    const WebFile *web{};       // streamed disc file (browser build)
    std::uint64_t position{};   // web and decrypted files track their own position
    std::string path{};
    std::int64_t async_result{};
    bool async_pending{};
    bool closing{};
    // Set once a PGD (DRM) file has been decrypted; reads come from here then.
    std::shared_ptr<const std::vector<std::uint8_t>> plain{};
    std::uint32_t pgd_offset{}; // where the PGD container starts in the file
    bool virtual_disc{};        // whole-disc LBN handle (disc0:/sce_lbn0x0_size...)
    std::uint64_t virtual_size{};
    std::string cached_relative{};
    // sceIoSetAsyncCallback: the callback fired once this fd's async op lands.
    std::int32_t async_cb{};
    std::uint32_t async_cb_arg{};
};

struct DirectoryEntry {
    std::string name;
    std::uint64_t size{};
    bool directory{};
    std::uint32_t lbn{}; // disc files: the sector number games read from st_private[0]
};

struct OpenDirectory {
    std::vector<DirectoryEntry> entries;
    std::size_t next{};
};

struct FixedPool {
    std::string name;
    std::uint32_t block_size{};
    std::uint32_t base{};
    std::int32_t memory_block{-1};
    std::vector<bool> used;
};

struct LoadedModule {
    std::string path;          // disc path relative to the disc root
    std::string name;          // from its module info
    std::uint32_t base{}, size{}, gp{}, start{}, stop{};
    std::int32_t block{-1};    // memory block, -1 for the main executable
    bool has_code{};           // recompiled code is registered
};

struct Mutex {
    std::string name;
    std::uint32_t attr{};
    std::int32_t count{};
    std::int32_t owner{}; // thread uid, 0 when unlocked
};

// Mailboxes pass pointers to guest message packets; the queue lives on the host.
struct Mailbox {
    std::string name;
    std::uint32_t attr{};
    std::deque<std::uint32_t> messages;
};

struct SubInterrupt {
    std::uint32_t handler{};
    std::uint32_t arg{};
    std::uint32_t gp{};
    bool enabled{};
    std::int32_t running{}; // uid of the handler thread while it runs
};

// A kernel callback registered with sceKernelRegisterCallback.  Lower priority
// numbers run first.  When pending and enabled, sceKernelCheckCallback will
// start the handler as a short-lived thread.
struct Callback {
    std::uint32_t entry{};   // function address
    std::uint32_t arg{};     // argument passed in a0
    std::uint32_t arg1{};    // argument passed in a1
    std::uint32_t gp{};      // global pointer passed in gp
    std::int32_t priority{}; // priority level (lower = higher priority)
    bool enabled{};          // whether the callback may run
    bool pending{};          // whether it is waiting to be dispatched
    std::int32_t running{};  // thread UID while the handler is running, 0 otherwise
    // Set for callbacks registered with sceKernelRegisterExitCallback.  These
    // are NOT VBlank-driven: the firmware only runs them from sceKernelExitGame.
    bool exit_only{};
    // Set for callbacks registered with sceUmdRegisterUMDCallBack.  The drive
    // status word is delivered in a1 on every dispatch, matching the firmware's
    // SceUmdCallback(int arg, int stat) signature.
    bool umd{};
};

struct GeCallback {
    std::uint32_t signal{};
    std::uint32_t signal_arg{};
    std::uint32_t finish{};
    std::uint32_t finish_arg{};
    std::uint32_t gp{};
};

struct GeEvent {
    std::int32_t callback{};
    bool finish{};
    std::uint32_t value{};
};

struct Alarm {
    std::uint64_t at{};
    std::uint32_t handler{};
    std::uint32_t common{};
    std::uint32_t gp{};
    std::int32_t running{};
};

struct AudioChannel {
    bool reserved{};
    std::uint32_t samples{};
    std::uint32_t format{}; // 0 stereo, 0x10 mono
    std::uint64_t busy_until_us{};
    std::uint64_t next_sample{};  // 44.1 kHz sample index where the next buffer starts
};

struct UtilityDialog {
    std::uint32_t status{};   // 0 none, 1 init, 2 visible, 3 quit, 4 finished
    std::uint32_t params{};
};

struct DisplayState {
    std::uint32_t framebuffer{};
    std::uint32_t stride{512};
    std::uint32_t format{3};
    std::uint32_t vcount{};
    std::uint64_t flips{}; // sceDisplaySetFrameBuf calls
    std::uint32_t flip_vcount{~0u}; // vblank the newest buffer change belongs to
};

class Kernel {
public:
    explicit Kernel(psprecomp::Runtime &runtime);

    // Host directories that disc0:/umd0: and ms0: resolve to.
    void set_roots(std::filesystem::path disc_root, std::filesystem::path memstick_root);
    void set_flash_root(std::filesystem::path flash_root) { flash_root_ = std::move(flash_root); }
    // PSP system language reported to the game (PSP_SYSTEMPARAM_LANGUAGE_*:
    // 0 Japanese, 1 English, 2 French, 3 Spanish, 4 German, 5 Italian, 6 Dutch,
    // 7 Portuguese, 8 Russian, 9 Korean, 10/11 Chinese).  Games pick their
    // voice/text folders from it, so it must match a language the disc ships.
    void set_language(std::uint32_t language) { language_ = language; }
    [[nodiscard]] std::uint32_t language() const noexcept { return language_; }
    // Parses "fr", "french", "2", ... into a language id; false if unknown.
    static bool parse_language(const std::string &text, std::uint32_t &language);
    // Marks a guest range (the loaded module image) as allocated.
    void reserve(std::uint32_t address, std::uint32_t size, std::string name);
    // Registers HLE handlers, logging fallbacks for every other import, and the
    // thread-return trampoline.
    void install(const std::vector<psprecomp::PspImport> &imports);
    // Creates and readies the loader thread that runs module_start.
    void boot(std::uint32_t entry, std::uint32_t gp, const std::string &module_path);
    // Records the executable and makes its exported libraries callable from
    // modules the game loads later.
    void add_main_module(const psprecomp::PspModuleInfo &info, std::uint32_t base, std::uint32_t size);

    // Runs one host frame: vblank, timers, then guest code for up to budget_ms.
    // Returns false once the guest exited, crashed or has no live threads.
    bool frame(double budget_ms);

    [[nodiscard]] const DisplayState &display() const noexcept { return display_; }
    [[nodiscard]] bool halted() const noexcept { return halted_; }
    [[nodiscard]] const std::string &halt_reason() const noexcept { return halt_reason_; }
    [[nodiscard]] std::uint64_t now_us() const;
    [[nodiscard]] Ge &ge() noexcept { return *ge_; }
    // Runs display lists (on a GE thread once started) and other GE-side work.
    [[nodiscard]] GeWorker &ge_worker() noexcept { return *ge_worker_; }
    // Total milliseconds the guest has spent waiting for the GE.
    [[nodiscard]] double ge_wait_ms() const noexcept { return ge_wait_ms_; }
    // Serves disc0:/umd0: from a streamed manifest instead of host files.
    bool enable_webfs(const std::string &manifest_path, const std::string &url_prefix);
    // Native builds complete simulated streaming reads here, once per frame.
    void poll_io();
    [[nodiscard]] const WebFs *webfs() const noexcept { return webfs_.get(); }

    // The cheat engine: load a user cheat file, toggle cheats, and apply them
    // once per frame.  See docs/cheats.md.
    [[nodiscard]] CheatEngine &cheats() noexcept { return cheats_; }
    [[nodiscard]] const CheatEngine &cheats() const noexcept { return cheats_; }
    // Parses and installs a cheat file's contents, keeping existing toggles by
    // id.  Returns the load result so a caller can report parse errors.
    CheatLoadResult load_cheats(const std::string &text);

    // The cheat finder: scan guest memory for a value and narrow the candidate
    // set frame by frame, so an address can be discovered without a debugger.
    // See docs/cheats.md ("Finding a cheat in the browser").
    [[nodiscard]] MemoryScanner &scanner() noexcept { return scanner_; }

    // Copies the visible 480x272 framebuffer into `rgba` (480*272*4 bytes).
    void read_framebuffer(std::uint8_t *rgba) const;

    // Entry point of the thread-return trampoline.
    void thread_returned(psprecomp::AllegrexContext &ctx);
    // Prints every thread with its state and what it waits on.
    void dump_threads() const;
    // Prints the blocking state (per-thread waits plus the last HLE call each
    // thread made, semaphores and open files) so a silent guest hang names what
    // it is stuck on.  Safe to call from the host between frames.
    void dump_diagnosis(const char *reason);

    // Host input: PSP button bits and analog stick (128 = centre).
    void set_pad(std::uint32_t buttons, std::uint8_t lx = 128u, std::uint8_t ly = 128u);
    // Receives interleaved stereo 16-bit PCM at 44.1 kHz as the guest outputs it.
    // Receives the mixed 44.1 kHz stereo output once per frame.
    using AudioSink = void (*)(const std::int16_t *samples, std::uint32_t frames);
    void set_audio_sink(AudioSink sink) { audio_sink_ = sink; }
    void savedata_choose(int index);
    [[nodiscard]] bool interrupt_pending() const noexcept { return ge_event_pending_.load(std::memory_order_relaxed); }

private:
    using Ctx = psprecomp::AllegrexContext;

    void start_thread(Thread &t, std::uint32_t arglen, const std::vector<std::uint8_t> &args);
    [[nodiscard]] std::uint64_t earliest_timed_wake() const;
    [[nodiscard]] bool waiting_for_ge() const;
    [[nodiscard]] bool waiting_for_io() const;

    void hle(const char *library, std::uint32_t nid, const char *name,
             void (Kernel::*handler)(Ctx &));
    void install_fallback(const psprecomp::PspImport &import);

    // Scheduling.
    Thread *current();
    Thread *thread(std::int32_t uid);
    void make_ready(Thread &t, bool front = false);
    Thread *pick_ready();
    void load_thread(Thread &t);
    // Saves the running thread (already advanced past its import) and switches.
    void block(Ctx &ctx, WaitType wait, std::uint32_t result);
    void reschedule(Ctx &ctx);
    void maybe_preempt(Ctx &ctx);
    void exit_thread(Ctx &ctx, std::int32_t status, bool remove);
    // Runs guest function `entry` on a temporary thread while the calling
    // thread waits; `done` maps the function's return value to the caller's.
    // Works even when the guest function blocks (for example on streamed I/O).
    // Runs a guest function on a temporary thread while the calling thread
    // waits; `done` turns its return value into the call's result. gp 0 keeps
    // the caller's.
    void call_guest(Ctx &ctx, std::uint32_t entry, std::initializer_list<std::uint32_t> args,
                    std::function<std::uint32_t(std::uint32_t)> done, std::uint32_t gp = 0u,
                    std::uint32_t stack_size = 0x8000u);
    void wake(Thread &t, std::uint32_t result);
    void poll_waits();
    bool try_satisfy_sema(Thread &t);
    bool try_satisfy_event(Thread &t);
    void begin_timeout(Thread &t, std::uint32_t timeout_address);
    void reset_context(Ctx &ctx) const;

    // Memory.
    std::int32_t allocate(std::string name, std::uint32_t type, std::uint32_t size, std::uint32_t address);
    [[nodiscard]] std::uint32_t largest_free() const;
    [[nodiscard]] std::uint32_t total_free() const;

    // Helpers.
    [[nodiscard]] std::string read_string(std::uint32_t address, std::size_t limit = 256) const;
    [[nodiscard]] std::filesystem::path host_path(const std::string &psp_path) const;
    // Path relative to the disc root, or nullopt-like empty flag for other devices.
    [[nodiscard]] bool disc_relative(const std::string &psp_path, std::string &relative) const;
    [[nodiscard]] bool stat_path(const std::string &psp_path, DirectoryEntry &entry) const;
    void write_stat(std::uint32_t address, const DirectoryEntry &entry);
    // Like the PSP, file and directory descriptors reuse the lowest free number
    // below 64; some games index tables with them. -1 when all are taken.
    [[nodiscard]] std::int32_t allocate_fd() const;
    // Games read a disc file's sector from its stat and then open it as
    // "disc0:/sce_lbn0x<sector>_size0x<bytes>". The extracted disc has no
    // sectors, so each file gets a stable one of its own the first time it is seen.
    std::uint32_t disc_lbn(const std::string &relative, std::uint64_t size);
    [[nodiscard]] std::string resolve_lbn_path(const std::string &psp_path) const;
    [[nodiscard]] bool parse_virtual_disc(const std::string &psp_path, std::uint64_t &size) const;
    void virtual_disc_read(Ctx &ctx, std::int32_t fd, std::uint32_t buffer, std::uint32_t length, bool async);
    std::map<std::string, std::uint32_t> lbn_by_path_;
    std::map<std::uint32_t, std::pair<std::string, std::uint64_t>> path_by_lbn_;
    std::uint32_t next_lbn_{0x1000u};
    void web_read(Ctx &ctx, std::int32_t fd, std::uint32_t buffer, std::uint32_t length, bool async);
    std::uint32_t plain_read(OpenFile &open, std::uint32_t buffer, std::uint32_t length);
    void with_file_contents(Ctx &ctx, std::int32_t fd,
                            std::function<std::uint32_t(OpenFile &, std::span<const std::uint8_t>)> use);
    void finish_async(std::int32_t fd);
    static void finish(Ctx &ctx, std::uint32_t result);
    static void finish64(Ctx &ctx, std::uint64_t result);
    std::int32_t new_uid() { return next_uid_++; }

    // ThreadManForUser.
    void sceKernelCreateThread(Ctx &ctx);
    void sceKernelStartThread(Ctx &ctx);
    void sceKernelExitThread(Ctx &ctx);
    void sceKernelExitDeleteThread(Ctx &ctx);
    void sceKernelDeleteThread(Ctx &ctx);
    void sceKernelTerminateDeleteThread(Ctx &ctx);
    void sceKernelSleepThread(Ctx &ctx);
    void sceKernelWakeupThread(Ctx &ctx);
    void sceKernelDelayThread(Ctx &ctx);
    void sceKernelGetThreadId(Ctx &ctx);
    void sceKernelGetThreadCurrentPriority(Ctx &ctx);
    void sceKernelChangeThreadPriority(Ctx &ctx);
    void sceKernelWaitThreadEnd(Ctx &ctx);
    void sceKernelCreateCallback(Ctx &ctx);
    void sceKernelRegisterCallback(Ctx &ctx);
    void sceKernelRegisterExitCallback(Ctx &ctx);
    void sceKernelCheckCallback(Ctx &ctx);
    // Runs a registered exit callback's handler, if any, before the game stops.
    bool run_exit_callback();
    void scePowerRegisterCallback(Ctx &ctx);
    void sceUmdRegisterUMDCallBack(Ctx &ctx);
    void sceKernelGetSystemTimeLow(Ctx &ctx);
    void sceKernelGetSystemTimeWide(Ctx &ctx);
    void sceKernelGetSystemTime(Ctx &ctx);
    void sysclock_to_usec(std::uint64_t clock, std::uint32_t low_addr, std::uint32_t high_addr);
    void sceKernelUSec2SysClock(Ctx &ctx);
    void sceKernelUSec2SysClockWide(Ctx &ctx);
    void sceKernelSysClock2USec(Ctx &ctx);
    void sceKernelSysClock2USecWide(Ctx &ctx);
    void sceKernelCreateSema(Ctx &ctx);
    void sceKernelCreateMutex(Ctx &ctx);
    void sceKernelDeleteMutex(Ctx &ctx);
    void sceKernelLockMutex(Ctx &ctx);
    void sceKernelTryLockMutex(Ctx &ctx);
    void sceKernelUnlockMutex(Ctx &ctx);
    void sceKernelCreateMbx(Ctx &ctx);
    void sceKernelDeleteMbx(Ctx &ctx);
    void sceKernelSendMbx(Ctx &ctx);
    void sceKernelReceiveMbx(Ctx &ctx);
    void sceKernelPollMbx(Ctx &ctx);
    void sceKernelRegisterSubIntrHandler(Ctx &ctx);
    void sceKernelReleaseSubIntrHandler(Ctx &ctx);
    void sceKernelEnableSubIntr(Ctx &ctx);
    void sceKernelDisableSubIntr(Ctx &ctx);
    void run_interrupts(std::uint32_t interrupt);
    std::int32_t start_handler(std::uint32_t entry, std::uint32_t gp, std::uint32_t a0, std::uint32_t a1,
                               std::function<std::uint32_t(std::uint32_t)> done);
    void sceKernelSetAlarm(Ctx &ctx);
    void sceKernelSetSysClockAlarm(Ctx &ctx);
    void sceKernelCancelAlarm(Ctx &ctx);
    void set_alarm(Ctx &ctx, std::uint64_t delay_us);
    void run_alarms();
    void sceKernelDeleteSema(Ctx &ctx);
    void sceKernelSignalSema(Ctx &ctx);
    void sceKernelWaitSema(Ctx &ctx);
    void sceKernelPollSema(Ctx &ctx);
    void sceKernelCreateEventFlag(Ctx &ctx);
    void sceKernelDeleteEventFlag(Ctx &ctx);
    void sceKernelSetEventFlag(Ctx &ctx);
    void sceKernelClearEventFlag(Ctx &ctx);
    void sceKernelWaitEventFlag(Ctx &ctx);
    void sceKernelPollEventFlag(Ctx &ctx);
    void sceKernelRotateThreadReadyQueue(Ctx &ctx);

    // SysMemUserForUser.
    void sceKernelMaxFreeMemSize(Ctx &ctx);
    void sceKernelTotalFreeMemSize(Ctx &ctx);
    void sceKernelAllocPartitionMemory(Ctx &ctx);
    void sceKernelFreePartitionMemory(Ctx &ctx);
    void sceKernelGetBlockHeadAddr(Ctx &ctx);
    void sceKernelDevkitVersion(Ctx &ctx);
    void sceKernelPrintf(Ctx &ctx);

    // LoadExecForUser / ModuleMgrForUser.
    void sceKernelExitGame(Ctx &ctx);
    void sceKernelSelfStopUnloadModule(Ctx &ctx);
    void sceKernelLoadModule(Ctx &ctx);
    void sceKernelStartModule(Ctx &ctx);
    void sceKernelStopModule(Ctx &ctx);
    void sceKernelUnloadModule(Ctx &ctx);
    void sceKernelStopUnloadSelfModuleWithStatus(Ctx &ctx);
    void sceKernelGetModuleIdByAddress(Ctx &ctx);
    void sceKernelGetModuleId(Ctx &ctx);
    void sceKernelQueryModuleInfo(Ctx &ctx);
    void sceKernelGetModuleIdList(Ctx &ctx);
    std::uint32_t load_module_image(const std::string &relative, std::span<const std::uint8_t> bytes);
    void register_exports(const psprecomp::PspModuleInfo &info);
    void unload_module(std::int32_t uid);
    [[nodiscard]] std::int32_t module_at(std::uint32_t address) const;
    void with_path_contents(Ctx &ctx, const std::string &psp_path,
                            std::function<std::uint32_t(std::span<const std::uint8_t>)> use);

    // StdioForUser.
    void sceKernelStdin(Ctx &ctx);
    void sceKernelStdout(Ctx &ctx);
    void sceKernelStderr(Ctx &ctx);

    // IoFileMgrForUser.
    void sceIoOpen(Ctx &ctx);
    void sceIoClose(Ctx &ctx);
    void sceIoRead(Ctx &ctx);
    void sceIoWrite(Ctx &ctx);
    void sceIoLseek(Ctx &ctx);
    void sceIoLseek32(Ctx &ctx);
    void sceIoGetstat(Ctx &ctx);
    void sceIoChdir(Ctx &ctx);
    void sceIoDopen(Ctx &ctx);
    void sceIoDread(Ctx &ctx);
    void sceIoDclose(Ctx &ctx);
    void sceIoOpenAsync(Ctx &ctx);
    void sceIoReadAsync(Ctx &ctx);
    void sceIoLseekAsync(Ctx &ctx);
    void sceIoLseek32Async(Ctx &ctx);
    void sceIoCloseAsync(Ctx &ctx);
    void sceIoWaitAsync(Ctx &ctx);
    void sceIoPollAsync(Ctx &ctx);
    void sceIoSetAsyncCallback(Ctx &ctx);
    void sceIoIoctl(Ctx &ctx);

    // sceDisplay / sceGe_user.
    void sceDisplaySetMode(Ctx &ctx);
    void sceDisplaySetFrameBuf(Ctx &ctx);
    void sceDisplayGetFrameBuf(Ctx &ctx);
    void sceDisplayWaitVblankStart(Ctx &ctx);
    void sceDisplayGetVcount(Ctx &ctx);
    void sceGeEdramGetAddr(Ctx &ctx);
    void sceGeEdramGetSize(Ctx &ctx);
    void sceGeListEnQueue(Ctx &ctx);
    void sceGeListUpdateStallAddr(Ctx &ctx);
    void sceGeGetCmd(Ctx &ctx);
    void sceGeSaveContext(Ctx &ctx);
    void sceGeRestoreContext(Ctx &ctx);
    void sceGeListSync(Ctx &ctx);
    void sceGeDrawSync(Ctx &ctx);
    void sceGeSetCallback(Ctx &ctx);
    void sceGeUnsetCallback(Ctx &ctx);
    void run_ge_callbacks();

    // UtilsForUser / Kernel_Library.
    void sceKernelLibcTime(Ctx &ctx);
    void sceKernelLibcGettimeofday(Ctx &ctx);
    void sceKernelCpuSuspendIntr(Ctx &ctx);
    void sceKernelMemcpy(Ctx &ctx);
    void sceKernelMemset(Ctx &ctx);
    void return_zero(Ctx &ctx);
    void return_one(Ctx &ctx);

    // devices.cpp: controller, audio, UMD, utility dialogs, misc kernel queries.
    void install_devices();
    void audio_output(Ctx &ctx, AudioChannel &channel, std::uint32_t buffer, std::uint32_t lvol, std::uint32_t rvol,
                      bool blocking = true);
    void dialog_get_status(Ctx &ctx, UtilityDialog &dialog);
    void sceCtrlPeekBufferPositive(Ctx &ctx);
    void sceCtrlReadBufferPositive(Ctx &ctx);
    void sceCtrlSetSamplingMode(Ctx &ctx);
    void sceCtrlGetSamplingMode(Ctx &ctx);
    void write_pad(std::uint32_t data, std::uint32_t count);
    void sceAudioChReserve(Ctx &ctx);
    void sceAudioChRelease(Ctx &ctx);
    void sceAudioOutputBlocking(Ctx &ctx);
    void sceAudioOutputPannedBlocking(Ctx &ctx);
    void sceAudioOutputPanned(Ctx &ctx);
    void sceAudioSetChannelDataLen(Ctx &ctx);
    void sceAudioGetChannelRestLength(Ctx &ctx);
    void sceAudioOutput2Reserve(Ctx &ctx);
    void sceAudioOutput2OutputBlocking(Ctx &ctx);
    void sceAudioOutput2ChangeLength(Ctx &ctx);
    void sceUmdCheckMedium(Ctx &ctx);
    void sceUmdGetDriveStat(Ctx &ctx);
    void sceUmdWaitDriveStatCB(Ctx &ctx);
    void sceUtilityGetSystemParamInt(Ctx &ctx);
    void sceCtrlReadLatch(Ctx &ctx);
    void sceCtrlPeekLatch(Ctx &ctx);
    void sceImposeGetLanguageMode(Ctx &ctx);
    void sceDisplayGetFramePerSec(Ctx &ctx);
    void sceUtilityMsgDialogInitStart(Ctx &ctx);
    void sceUtilityMsgDialogGetStatus(Ctx &ctx);
    void sceUtilityMsgDialogShutdownStart(Ctx &ctx);
    void sceKernelCreateFpl(Ctx &ctx);
    void sceKernelDeleteFpl(Ctx &ctx);
    void sceKernelAllocateFpl(Ctx &ctx);
    void sceKernelFreeFpl(Ctx &ctx);
    void sceKernelTryAllocateFpl(Ctx &ctx);
    void sceKernelReferThreadStatus(Ctx &ctx);
    void sceKernelReferEventFlagStatus(Ctx &ctx);
    void sceKernelLibcClock(Ctx &ctx);
    void sceRtcGetCurrentClockLocalTime(Ctx &ctx);
    void sceRtcGetCurrentTick(Ctx &ctx);
    void sceRtcGetTickResolution(Ctx &ctx);
    void sceKernelVolatileMemLock(Ctx &ctx);

    psprecomp::Runtime &rt_;
    std::unique_ptr<Ge> ge_;
    std::unique_ptr<GeWorker> ge_worker_;
    double ge_wait_ms_{};
    std::unique_ptr<WebFs> webfs_;
    std::map<std::int32_t, Thread> threads_;
    std::map<std::int32_t, Semaphore> semaphores_;
    std::map<std::int32_t, EventFlag> event_flags_;
    std::map<std::int32_t, MemoryBlock> blocks_;
    std::map<std::int32_t, OpenFile> files_;
    std::map<std::int32_t, OpenDirectory> directories_;
    std::map<std::int32_t, LoadedModule> modules_;
    std::map<std::int32_t, FixedPool> fpls_;
    std::map<std::int32_t, Mutex> mutexes_;
    std::map<std::int32_t, Mailbox> mailboxes_;
    std::map<std::pair<std::uint32_t, std::uint32_t>, SubInterrupt> sub_interrupts_; // (interrupt, sub) -> handler
    std::map<std::int32_t, Callback> callbacks_; // uid -> kernel callback
    std::map<std::int32_t, Alarm> alarms_;
    std::map<std::int32_t, GeCallback> ge_callbacks_;
    std::mutex ge_events_mutex_;
    std::deque<GeEvent> ge_events_;
    std::int32_t ge_callback_running_{0};
    std::atomic<bool> ge_event_pending_{false};
    struct GuestCall {
        std::int32_t caller{};
        std::function<std::uint32_t(std::uint32_t)> done;
    };
    std::map<std::int32_t, GuestCall> guest_calls_;   // callback thread uid -> waiting caller

    // mpeg.cpp: sceMpeg (movies are consumed without decoding for now).
    void install_mpeg();
    void install_sas();      // sas.cpp: the SAS voice synthesizer (sound effects)
    // Mixes a buffer that starts playing at `start_sample` into the output.
    void mix_audio(std::uint64_t start_sample, const std::int16_t *stereo, std::uint32_t frames,
                   std::int32_t left_volume, std::int32_t right_volume);
    void drain_audio(std::uint64_t until_us);
    std::vector<std::int32_t> mix_ring_;    // stereo, indexed by sample % ring size
    std::uint64_t mix_read_{};              // next sample handed to the sink
    std::vector<std::int16_t> mix_out_;
    std::shared_ptr<void> sas_;             // sas.cpp state
    void install_atrac();    // atrac.cpp: ATRAC3/ATRAC3+ streams (music, speech)
    void install_savedata();
    std::shared_ptr<void> savedata_;
    // cheats.cpp: the cheat engine and its host actions.
    void install_cheats() ;
    CheatEngine cheats_;
    MemoryScanner scanner_;
    // When a live cheat sets frozen/held, the timestamp getters return a fixed
    // value instead of now_us(); the base is captured on the frame it is armed.
    bool cheat_freeze_clock_{false};
    std::uint64_t cheat_frozen_us_{0u};
    std::shared_ptr<void> atrac_;           // atrac.cpp state
    void install_fonts();
    std::shared_ptr<void> fonts_;
    std::array<AudioChannel, 8> audio_channels_{};
    AudioChannel audio_output2_{};
    AudioSink audio_sink_{};
    UtilityDialog msg_dialog_{};
    std::uint32_t pad_buttons_{};
    std::uint32_t latch_make_{}, latch_break_{}; // buttons pressed / released since the last sceCtrlReadLatch
    std::uint8_t pad_lx_{128u};
    std::uint8_t pad_ly_{128u};
    std::uint32_t pad_read_vcount_{~0u};
    std::uint32_t pad_mode_{};
    std::int32_t current_uid_{-1};
    std::int32_t next_uid_{0x100};
    std::uint64_t ready_sequence_{};
    // Guest time is frame-based: each host frame is one vblank period, real
    // time advances it within the frame, and an idle guest warps forward to its
    // next timer instead of stalling the browser.  warp_us_ is the offset into
    // the current frame the warp has reached (never past its end); now_us()
    // takes the larger of it and real elapsed time, never their sum.
    std::uint64_t frame_start_guest_us_{};
    std::uint64_t warp_us_{};
    std::int64_t frame_real_start_ns_{};
    DisplayState display_{};
    bool throttle_flips_{std::getenv("PSPWEB_NO_FLIP_THROTTLE") == nullptr};
    std::filesystem::path disc_root_{"."};
    std::filesystem::path memstick_root_{"."};
    std::filesystem::path flash_root_{"flash0"};
    std::uint32_t language_{1u}; // English
    std::string cwd_{"disc0:/"};
    std::set<std::string> registered_;
    std::set<std::string> fallback_logged_;
    bool halted_{};
    std::string halt_reason_;

    // Progress watchdog.  hle_calls_ counts the HLE entries the guest made; the
    // frame loop samples it and, when it has not moved for kStallFrames frames,
    // prints dump_diagnosis() once.  last_hle_* remember the most recent HLE
    // call per thread so the dump can name the call a blocked thread came from.
    std::uint64_t hle_calls_{};
    std::uint64_t last_progress_hle_calls_{};
    int idle_frames_{};
    bool diagnosed_{};
    std::map<std::int32_t, std::string> last_hle_;
};

} // namespace pspweb
