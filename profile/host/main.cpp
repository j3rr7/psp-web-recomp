// Host entry for the web profile.  The same code builds natively (headless,
// dumps the framebuffer to a PPM for checking) and with Emscripten (presents
// every frame to a <canvas> from requestAnimationFrame).

#include "ge_gl.hpp"
#include "kernel.hpp"

#include "psprecomp/elf32.hpp"
#include "psprecomp/interpreter.hpp"
#include "psprecomp/runtime.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#if defined(__EMSCRIPTEN__)
#include <emscripten/emscripten.h>
#include <emscripten/html5.h>
#else
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <atomic>
#include <chrono>
#include <thread>
#endif

namespace psprecomp {
void register_dynamic_code();
}

namespace {

constexpr std::uint32_t kWidth = 480u;
constexpr std::uint32_t kHeight = 272u;

struct Session {
    std::unique_ptr<psprecomp::Runtime> runtime;
    std::unique_ptr<pspweb::Kernel> kernel;
    std::unique_ptr<pspweb::GeGl> gl;     // null: software rendering; lives on the GE thread
    GLuint out_fbo{}, out_texture{};       // native presentation target
    std::vector<std::uint8_t> rgba = std::vector<std::uint8_t>(kWidth * kHeight * 4u);
    std::atomic<int> scale{1};             // GL internal resolution multiple (set on the GE thread)
    int max_scale{1};
    bool use_gl{};                         // the GL renderer is wanted (it may still be starting)
    std::atomic<bool> gl_ready{false};     // set on the GE thread once the renderer is up
    bool running{};
};

Session g_session;
std::filesystem::path g_dynamic_listing;
// Set from the page (see pspweb_set_paused).  While true the guest stops
// stepping but the session, its log and its state stay alive for inspection.
bool g_paused = false;

void capture_dynamic_code(std::uint32_t address, const std::uint32_t *words, std::size_t count) {
    std::ofstream out(g_dynamic_listing, std::ios::app);
    out << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << address;
    for (std::size_t i = 0; i < count; ++i) out << ' ' << std::setw(8) << words[i];
    out << '\n';
}

bool start_session(const std::string &module_path, const std::string &disc_root,
                   const std::string &memstick_root, const std::string &guest_path,
                   const std::string &manifest = {}, const std::string &data_url = {}) {
    auto &s = g_session;
    s.runtime = std::make_unique<psprecomp::Runtime>();
    auto &rt = *s.runtime;
    const auto elf = psprecomp::Elf32Image::from_file(module_path);
    const std::uint32_t load_base = psprecomp::kDefaultPspUserLoadBase;
    const auto relocations = elf.load_and_relocate(rt.memory(), load_base);
    const auto module = elf.find_module_info(rt.memory(), load_base);
    if (!module) {
        std::cerr << "[pspweb] no module info in " << module_path << "\n";
        return false;
    }
    const auto imports = elf.scan_imports(rt.memory(), *module);

    std::uint32_t image_end = load_base;
    for (std::size_t i = 0; i < elf.segments().size(); ++i) {
        const auto &segment = elf.segments()[i];
        if (segment.type != 1u) continue;
        image_end = std::max(image_end, elf.segment_runtime_address(i, load_base) + segment.memory_size);
    }

    psprecomp::register_generated_functions(rt);
    psprecomp::register_dynamic_code();
    psprecomp::set_runtime_missing_code_handler(&psprecomp::run_dynamic_code);
#if !defined(__EMSCRIPTEN__)
    g_dynamic_listing = std::filesystem::path(module_path).parent_path() / "dynamic.txt";
    psprecomp::set_dynamic_code_capture(&capture_dynamic_code);
#endif
    s.kernel = std::make_unique<pspweb::Kernel>(rt);
    s.kernel->reserve(load_base, image_end - load_base, "module:" + module->name);
    s.kernel->set_roots(disc_root, memstick_root);
    s.kernel->set_flash_root(std::filesystem::path(module_path).parent_path() / "flash0");
    // System language: PSPWEB_LANGUAGE (the page sets it from ?lang=) wins,
    // else a one-line "language" file next to EBOOT.BIN (a per-game default for
    // discs that only ship some languages), else English.
    {
        std::string wanted, source;
        if (const char *env = std::getenv("PSPWEB_LANGUAGE"); env != nullptr && *env != '\0') {
            wanted = env;
            source = "PSPWEB_LANGUAGE";
        } else {
            const auto file = std::filesystem::path(module_path).parent_path() / "language";
            if (std::ifstream in(file); in && std::getline(in, wanted)) source = file.string();
        }
        if (!source.empty()) {
            std::uint32_t language = 1u;
            if (pspweb::Kernel::parse_language(wanted, language)) {
                s.kernel->set_language(language);
                std::cout << "[pspweb] system language " << language << " (" << wanted << ", from " << source << ")\n";
            } else {
                std::cerr << "[pspweb] unknown language '" << wanted << "' in " << source << ", using English\n";
            }
        }
    }
    if (!manifest.empty() && !s.kernel->enable_webfs(manifest, data_url))
        std::cerr << "[pspweb] no disc manifest at " << manifest << ", using local files\n";
    s.kernel->add_main_module(*module, load_base, image_end - load_base);
    s.kernel->install(imports);
    s.kernel->boot(elf.runtime_entry(load_base), module->gp, guest_path);
    s.running = true;

    std::cout << "[pspweb] module " << module->name << " loaded at 0x" << std::hex << load_base << "-0x"
              << image_end << std::dec << ", " << imports.size() << " imports, " << relocations.total
              << " relocations, " << rt.function_count() << " registered entries\n";
    return true;
}

// Switches the GE to the GL backend; a GL ES 3 context must be current.
bool enable_gl() {
    auto &s = g_session;
    auto gl = std::make_unique<pspweb::GeGl>(s.runtime->memory());
    if (!gl->init()) {
        std::cerr << "[pspweb] GL backend failed to initialize, using software rendering\n";
        return false;
    }
    s.gl = std::move(gl);
    s.kernel->ge().set_gl(s.gl.get());
    std::cout << "[pspweb] GL renderer: " << reinterpret_cast<const char *>(glGetString(GL_RENDERER)) << "\n";
    return true;
}

// Runs one guest frame; returns false when done.
bool step(double budget_ms) {
    auto &s = g_session;
    if (!s.running) return false;
    s.running = s.kernel->frame(budget_ms);
    if (s.use_gl) {
        s.kernel->ge_worker().post([] {
            if (auto *gl = g_session.gl.get()) gl->next_frame();
        });
    } else {
        s.kernel->read_framebuffer(s.rgba.data());
    }
    if (!s.running) std::cout << "[pspweb] guest stopped: " << s.kernel->halt_reason() << "\n";
    return s.running;
}

// Queues drawing the displayed framebuffer with GL into `fbo` (0 = the canvas),
// after the GE work queued so far.
void present_gl(GLuint fbo) {
    auto &s = g_session;
    const auto &d = s.kernel->display();
    auto &worker = s.kernel->ge_worker();
    worker.post([&worker, fb = d.framebuffer, stride = d.stride, format = d.format, fbo] {
        auto *gl = g_session.gl.get();
        if (gl == nullptr) return;
        const int scale = gl->render_scale();
        gl->present(fb, stride, format, fbo, static_cast<int>(kWidth) * scale, static_cast<int>(kHeight) * scale);
        worker.mark_presented();
    });
}

// Runs on the thread with the GL context: sets up the GL renderer.
bool enable_gl_here() {
    if (!enable_gl()) return false;
    g_session.max_scale = g_session.gl->max_render_scale();
    g_session.gl_ready.store(true);
    return true;
}

void write_ppm(const std::string &path, const std::vector<std::uint8_t> &rgba, std::uint32_t width, std::uint32_t height) {
    std::ofstream out(path, std::ios::binary);
    out << "P6\n" << width << " " << height << "\n255\n";
    for (std::uint32_t i = 0; i < width * height; ++i) out.write(reinterpret_cast<const char *>(&rgba[i * 4u]), 3);
}

// Size of the presented picture: the PSP screen times the internal scale.
int out_width() { return static_cast<int>(kWidth) * g_session.scale.load(); }
int out_height() { return static_cast<int>(kHeight) * g_session.scale.load(); }

} // namespace

#if defined(__EMSCRIPTEN__)

namespace {
double g_last_frame_ms = 0.0;

// ?profile in the page URL sets PSPWEB_FRAME_PROFILE: a breakdown of each
// game frame is shown in the status bar every 60 frames.
struct WebProfile {
    bool enabled = std::getenv("PSPWEB_FRAME_PROFILE") != nullptr;
    int frames = 0, steps = 0;
    double step_ms = 0.0, ge_busy_from = 0.0, ge_wait_from = 0.0, gl_from = 0.0;
} g_web_profile;

void report_web_profile() {
    auto &p = g_web_profile;
    if (!p.enabled || ++p.frames < 60) return;
    auto &s = g_session;
    auto &worker = s.kernel->ge_worker();
    const double steps = std::max(p.steps, 1);
    const double ge_ms = (worker.busy_ms() - p.ge_busy_from) / steps;
    const double wait_ms = (s.kernel->ge_wait_ms() - p.ge_wait_from) / steps;
    const bool ready = s.gl_ready.load();
    const double gl_ms = ready ? s.gl->flush_ms() / steps : 0.0;
    // With a GE thread the guest's own time excludes waiting for it; without
    // one the GE runs inside the guest's time.
    const double game_ms = p.step_ms / steps - (worker.threaded() ? wait_ms : ge_ms);
    auto &ge = s.kernel->ge();
    char text[256];
    std::snprintf(text, sizeof text, "game %.1f | GE %.1f%s (GL %.1f) | waiting for GE %.1f | draws %.0f | tris %.0fk | readbacks %.1f",
                  game_ms, ge_ms, worker.threaded() ? " on its own thread" : "", gl_ms, wait_ms,
                  ready ? s.gl->draw_calls() / steps : 0.0, static_cast<double>(ge.stats().triangles) / steps / 1000.0,
                  ready ? s.gl->downloads() / steps : 0.0);
    EM_ASM({ if (Module.pspProfile) Module.pspProfile(UTF8ToString($0)); }, text);
    ge.reset_stats();
    if (ready) s.gl->reset_counters();
    p = WebProfile{};
    p.ge_busy_from = worker.busy_ms();
    p.ge_wait_from = s.kernel->ge_wait_ms();
}

void web_frame() {
    auto &s = g_session;
    if (g_paused) return;
    auto &worker = s.kernel->ge_worker();
    // Advance the guest at the PSP's 59.94 Hz regardless of the display rate.
    const double now = emscripten_get_now();
    static double ge_busy_last = 0.0, ge_wait_last = 0.0;
    if (g_last_frame_ms == 0.0) g_last_frame_ms = now - 16.683;
    int frames = 0;
    while (now - g_last_frame_ms >= 16.683 && frames < 2) {
        g_last_frame_ms += 16.683;
        step(12.0);
        ++frames;
    }
    g_web_profile.steps += frames;
    if (now - g_last_frame_ms > 100.0) g_last_frame_ms = now;
    if (frames == 0) return;
    const double stepped = emscripten_get_now();
    g_web_profile.step_ms += stepped - now;
    if (s.use_gl) {
        present_gl(0);
        report_web_profile();
        // The frame's cost is whichever thread was busier: the guest (not
        // counting time spent waiting for the GE) or the GE.
        const double ge_busy = worker.busy_ms(), ge_wait = s.kernel->ge_wait_ms();
        double cost = stepped - now - (ge_wait - ge_wait_last);
        if (worker.threaded()) cost = std::max(cost, ge_busy - ge_busy_last);
        ge_busy_last = ge_busy;
        ge_wait_last = ge_wait;
        EM_ASM({ if (Module.pspFrame) Module.pspFrame($0, $1); }, cost, frames);
    } else {
        EM_ASM({ if (Module.pspPresent) Module.pspPresent(HEAPU8.subarray($0, $0 + $1 * $2 * 4), $1, $2); },
               s.rgba.data(), kWidth, kHeight);
    }
    if (!s.running) {
        EM_ASM({ if (Module.pspStatus) Module.pspStatus(UTF8ToString($0)); }, s.kernel->halt_reason().c_str());
    }
}
} // namespace

// Sets the internal resolution (1..4 times 480x272) and resizes the canvas.
// Returns the scale that will be used, or 0 while the GL renderer is not up yet.
extern "C" EMSCRIPTEN_KEEPALIVE int pspweb_set_render_scale(int scale) {
    auto &s = g_session;
    if (!s.gl_ready.load()) return 0;
    scale = std::clamp(scale, 1, s.max_scale);
    s.kernel->ge_worker().post([scale] {
        auto *gl = g_session.gl.get();
        const int used = gl->set_render_scale(scale);
        emscripten_set_canvas_element_size("#canvas", static_cast<int>(kWidth) * used, static_cast<int>(kHeight) * used);
        g_session.scale.store(used);
    });
    return scale;
}

// Mixed audio goes to the page, which plays it through Web Audio.
void web_audio_sink(const std::int16_t *samples, std::uint32_t frames) {
    EM_ASM({ if (Module.pspAudio) Module.pspAudio(HEAP16.subarray($0 >> 1, ($0 >> 1) + $1 * 2)); }, samples, frames);
}

extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_set_pad(std::uint32_t buttons, std::uint32_t lx, std::uint32_t ly) {
    if (g_session.kernel) g_session.kernel->set_pad(buttons, static_cast<std::uint8_t>(lx), static_cast<std::uint8_t>(ly));
}

// Pause/resume the guest from the page.  Pausing dumps the current thread and
// wait state to the log (so a hang can be captured and downloaded) and stops
// stepping without tearing the session down; resuming continues where it left
// off.  Returns the resulting paused state.
extern "C" EMSCRIPTEN_KEEPALIVE int pspweb_set_paused(int paused) {
    g_paused = paused != 0;
    if (g_paused && g_session.kernel) {
        std::cout << "[pspweb] paused by user at vcount " << g_session.kernel->display().vcount << "\n";
        g_session.kernel->dump_diagnosis("paused");
    } else {
        std::cout << "[pspweb] resumed\n";
    }
    EM_ASM({ if (Module.pspStatus) Module.pspStatus($0 ? "paused" : "running"); }, g_paused ? 1 : 0);
    return g_paused ? 1 : 0;
}

extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_save_choice(int index) {
    if (g_session.kernel) g_session.kernel->savedata_choose(index);
}

// Cheat bridge.  The page loads a file's text, toggles cheats by id, and reads
// back the current list as JSON through Module.pspCheats.  See docs/cheats.md.
namespace {
// Escapes the few characters that matter for a JSON string value.
std::string json_escape(const std::string &text) {
    std::string out;
    out.reserve(text.size() + 2u);
    for (char c : text) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20u) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned char>(c));
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

// Reports the loaded cheats and any errors to the page.
void report_cheats() {
    if (!g_session.kernel) return;
    const auto &cheats = g_session.kernel->cheats();
    std::string out = "{\"cheats\":[";
    bool first = true;
    for (const auto &cheat : cheats.cheats()) {
        if (!first) out += ',';
        first = false;
        out += "{\"id\":\"" + json_escape(cheat.id) + "\",\"name\":\"" + json_escape(cheat.name) +
               "\",\"enabled\":" + (cheat.enabled ? "true" : "false") + "}";
    }
    out += "],\"errors\":[";
    first = true;
    for (const auto &error : cheats.errors()) {
        if (!first) out += ',';
        first = false;
        out += '"' + json_escape(error) + '"';
    }
    out += "]}";
    EM_ASM({ if (Module.pspCheats) Module.pspCheats(UTF8ToString($0)); }, out.c_str());
}
} // namespace

// Loads cheat text (the contents of a .cheat file).  Returns 1 when at least one
// cheat parsed, 0 otherwise; either way the page is told the full result.
extern "C" EMSCRIPTEN_KEEPALIVE int pspweb_load_cheats(const char *text) {
    if (!g_session.kernel || text == nullptr) return 0;
    const auto result = g_session.kernel->load_cheats(text);
    for (const auto &error : result.errors) std::cerr << "[cheat] " << error << "\n";
    std::cout << "[cheat] loaded " << result.cheats.size() << " cheats\n";
    report_cheats();
    return result.cheats.empty() ? 0 : 1;
}

// Enables or disables one cheat by id.  An empty id toggles every cheat.
extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_set_cheat(const char *id, int enabled) {
    if (!g_session.kernel) return;
    const std::string key = id != nullptr ? id : "";
    if (key.empty()) g_session.kernel->cheats().set_all_enabled(enabled != 0);
    else if (!g_session.kernel->cheats().set_enabled(key, enabled != 0))
        std::cerr << "[cheat] no cheat with id " << key << "\n";
    report_cheats();
}

// Re-reports the loaded cheats (the page calls this when it opens the panel).
extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_cheats_ping() { report_cheats(); }

// ---------------------------------------------------------------------------
// Memory inspector / cheat finder bridge.  The page uses these to read memory
// for a hex viewer and to drive the scanner; results come back as JSON through
// Module.pspScan.  See docs/cheats.md.
extern "C" EMSCRIPTEN_KEEPALIVE std::uint32_t pspweb_peek8(std::uint32_t address) {
    return g_session.runtime ? g_session.runtime->memory().load8(address) : 0u;
}
extern "C" EMSCRIPTEN_KEEPALIVE std::uint32_t pspweb_peek16(std::uint32_t address) {
    return g_session.runtime ? g_session.runtime->memory().load16(address) : 0u;
}
extern "C" EMSCRIPTEN_KEEPALIVE std::uint32_t pspweb_peek32(std::uint32_t address) {
    return g_session.runtime ? g_session.runtime->memory().load32(address) : 0u;
}
// Writes one 32-bit word from the UI.  A temporary poke for probing an address;
// a cheat file is the durable way to change memory.
extern "C" EMSCRIPTEN_KEEPALIVE int pspweb_poke32(std::uint32_t address, std::uint32_t value) {
    if (!g_session.runtime || !g_session.runtime->memory().contains(address, 4u)) return 0;
    g_session.runtime->memory().store32(address, value);
    return 1;
}
// Copies `length` bytes of guest memory into `out` (a wasm-heap buffer the page
// allocates), so a hex dump costs one call rather than one per byte.  Returns
// the number of bytes copied; a range that is not wholly valid copies nothing.
extern "C" EMSCRIPTEN_KEEPALIVE std::uint32_t pspweb_read_range(std::uint32_t address, std::uint32_t length, std::uint8_t *out) {
    if (!g_session.runtime || out == nullptr || length == 0u) return 0u;
    auto &memory = g_session.runtime->memory();
    if (!memory.contains(address, length)) return 0u;
    memory.copy_out(address, std::span<std::uint8_t>(out, length));
    return length;
}

// Hex-dump helper for the page.  The page cannot rely on Module.HEAPU8 being
// exported, so instead of returning a pointer to read, this copies the range
// into `out` and hands the bytes to Module.pspDump as a Uint8Array through
// EM_ASM (the same way the audio sink passes samples).  `out` is a
// Module._malloc buffer the page owns.
extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_dump_to_js(std::uint32_t address, std::uint32_t length, std::uint8_t *out) {
    const std::uint32_t got = pspweb_read_range(address, length, out);
    EM_ASM({
        if (Module.pspDump) Module.pspDump($0, HEAPU8.subarray($1, $1 + $2));
    }, address, out, got);
}

namespace {
// Reports a scan result to the page as JSON.
void report_scan(const pspweb::ScanResult &result) {
    std::string out = "{\"ok\":";
    out += result.ok ? "true" : "false";
    out += ",\"total\":" + std::to_string(result.total);
    out += ",\"note\":\"" + json_escape(result.note) + "\"";
    out += ",\"hits\":[";
    bool first = true;
    for (const pspweb::ScanHit &hit : result.hits) {
        if (!first) out += ',';
        first = false;
        out += "{\"address\":" + std::to_string(hit.address) + ",\"value\":" + std::to_string(hit.value) + "}";
    }
    out += "]}";
    EM_ASM({ if (Module.pspScan) Module.pspScan(UTF8ToString($0)); }, out.c_str());
}
} // namespace

// First scan.  `unknown` != 0 starts from every address in the region; `width`
// is 1/2/4 bytes; `value` is the value to match when not scanning for unknown.
extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_scan_first(int width, std::uint32_t value, int unknown) {
    if (!g_session.kernel) return;
    const pspweb::ScanWidth w = width == 1 ? pspweb::ScanWidth::B8 : width == 2 ? pspweb::ScanWidth::B16 : pspweb::ScanWidth::B32;
    const pspweb::ScanResult result = g_session.kernel->scanner().first_scan(
        pspweb::ScanRegion::UserRam, w, value, unknown != 0);
    std::cout << "[scan] " << result.note << "\n";
    report_scan(result);
}

// Filter.  `filter` is one of equal/not-equal/changed/unchanged/increased/
// decreased; `value` is used by equal/not-equal.  `pspweb_scan_refresh` re-reads
// the values without narrowing the set.
extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_scan_filter(const char *filter, std::uint32_t value) {
    if (!g_session.kernel) return;
    const std::string key = filter != nullptr ? filter : "changed";
    const pspweb::ScanFilter f = key == "equal"    ? pspweb::ScanFilter::Equal
                       : key == "not-equal" ? pspweb::ScanFilter::NotEqual
                       : key == "unchanged" ? pspweb::ScanFilter::Unchanged
                       : key == "increased" ? pspweb::ScanFilter::Increased
                       : key == "decreased" ? pspweb::ScanFilter::Decreased
                                            : pspweb::ScanFilter::Changed;
    report_scan(g_session.kernel->scanner().filter(f, value));
}

extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_scan_refresh() {
    if (!g_session.kernel) return;
    report_scan(g_session.kernel->scanner().refresh());
}

extern "C" EMSCRIPTEN_KEEPALIVE void pspweb_scan_clear() {
    if (g_session.kernel) g_session.kernel->scanner().clear();
}

namespace {
// Creates the WebGL2 context on the calling thread (the GE thread when there
// is one: the canvas has been handed to it) and the GL renderer.
void init_web_gl(bool threaded) {
    EmscriptenWebGLContextAttributes attributes;
    emscripten_webgl_init_context_attributes(&attributes);
    attributes.majorVersion = 2;
    attributes.minorVersion = 0;
    attributes.alpha = false;
    attributes.depth = false;
    attributes.stencil = false;
    attributes.antialias = false;
    attributes.preserveDrawingBuffer = false;
    if (threaded) attributes.proxyContextToMainThread = EMSCRIPTEN_WEBGL_CONTEXT_PROXY_DISALLOW;
    const EMSCRIPTEN_WEBGL_CONTEXT_HANDLE context = emscripten_webgl_create_context("#canvas", &attributes);
    if (context <= 0) {
        std::cerr << "[pspweb] WebGL2 is not available, using software rendering\n";
        return;
    }
    emscripten_webgl_make_context_current(context);
    enable_gl_here();
}
} // namespace

int main() {
    const bool streamed = std::ifstream("/game/disc.manifest").good();
    if (!start_session("/game/EBOOT.BIN", "/game/disc", "/game/ms0", PSPWEB_GUEST_PATH,
                       streamed ? "/game/disc.manifest" : "", "disc"))
        return 1;
    // The GE gets a thread of its own (with the canvas) unless ?threads=0 or the
    // browser cannot draw WebGL2 on an OffscreenCanvas.
    const bool threaded = EM_ASM_INT({
        if (/[?&]threads=0(&|$)/.test(location.search)) return 0;
        try {
            return typeof OffscreenCanvas != 'undefined' && !!new OffscreenCanvas(1, 1).getContext('webgl2') ? 1 : 0;
        } catch (e) {
            return 0;
        }
    }) != 0;
    g_session.use_gl = true;
    if (threaded) {
        g_session.kernel->ge_worker().start([] { init_web_gl(true); }, "#canvas");
    } else {
        init_web_gl(false);
    }
    std::cout << "[pspweb] GE " << (g_session.kernel->ge_worker().threaded() ? "on its own thread" : "on the main thread") << "\n";
    g_session.kernel->set_audio_sink(&web_audio_sink);
    EM_ASM({ if (Module.pspStatus) Module.pspStatus("running"); });
    emscripten_set_main_loop(web_frame, 0, false);
    return 0;
}

#else

namespace {
// Headless GL ES 3 context (Mesa surfaceless platform) for testing the GL path.
bool create_headless_gl() {
    auto get_display = reinterpret_cast<PFNEGLGETPLATFORMDISPLAYEXTPROC>(eglGetProcAddress("eglGetPlatformDisplayEXT"));
    EGLDisplay display = get_display != nullptr
        ? get_display(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, nullptr)
        : eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major = 0, minor = 0;
    if (display == EGL_NO_DISPLAY || !eglInitialize(display, &major, &minor)) {
        std::cerr << "[pspweb] EGL initialisation failed\n";
        return false;
    }
    eglBindAPI(EGL_OPENGL_ES_API);
    const EGLint config_attributes[] = {EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT, EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_NONE};
    EGLConfig config = nullptr;
    EGLint count = 0;
    eglChooseConfig(display, config_attributes, &config, 1, &count);
    const EGLint context_attributes[] = {EGL_CONTEXT_MAJOR_VERSION, 3, EGL_NONE};
    EGLContext context = eglCreateContext(display, count > 0 ? config : EGL_NO_CONFIG_KHR, EGL_NO_CONTEXT, context_attributes);
    if (context == EGL_NO_CONTEXT || !eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, context)) {
        std::cerr << "[pspweb] EGL context creation failed (0x" << std::hex << eglGetError() << std::dec << ")\n";
        return false;
    }
    return true;
}

// Dumps are GL captures at the internal scale, or the guest framebuffer.
std::uint32_t capture_width() { return g_session.gl ? static_cast<std::uint32_t>(out_width()) : kWidth; }
std::uint32_t capture_height() { return g_session.gl ? static_cast<std::uint32_t>(out_height()) : kHeight; }

// --wav: everything the game plays, written out at the end.
std::vector<std::int16_t> g_wav;
void wav_sink(const std::int16_t *samples, std::uint32_t frames) { g_wav.insert(g_wav.end(), samples, samples + frames * 2u); }

void write_wav(const std::string &path) {
    std::ofstream out(path, std::ios::binary);
    auto u32 = [&](std::uint32_t v) { out.write(reinterpret_cast<const char *>(&v), 4); };
    auto u16 = [&](std::uint16_t v) { out.write(reinterpret_cast<const char *>(&v), 2); };
    const auto bytes = static_cast<std::uint32_t>(g_wav.size() * 2u);
    out.write("RIFF", 4); u32(36u + bytes); out.write("WAVEfmt ", 8);
    u32(16u); u16(1u); u16(2u); u32(44100u); u32(44100u * 4u); u16(4u); u16(16u);
    out.write("data", 4); u32(bytes);
    out.write(reinterpret_cast<const char *>(g_wav.data()), bytes);
}

// Presents with GL and reads the result back into session.rgba (top row first).
void capture_gl() {
    auto &s = g_session;
    if (!s.gl) return;
    present_gl(s.out_fbo);
    s.kernel->ge_worker().call([] {
        auto &session = g_session;
        const auto width = static_cast<std::uint32_t>(out_width()), height = static_cast<std::uint32_t>(out_height());
        std::vector<std::uint8_t> pixels(width * height * 4u);
        glBindFramebuffer(GL_FRAMEBUFFER, session.out_fbo);
        glReadPixels(0, 0, static_cast<GLsizei>(width), static_cast<GLsizei>(height), GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
        session.rgba.resize(width * height * 4u);
        for (std::uint32_t y = 0; y < height; ++y)
            std::memcpy(&session.rgba[y * width * 4u], &pixels[(height - 1u - y) * width * 4u], width * 4u);
    });
}

// Runs on the GE thread: headless GL context, renderer and capture target.
void init_native_gl() {
    auto &s = g_session;
    if (!create_headless_gl() || !enable_gl_here()) return;
    s.scale.store(s.gl->set_render_scale(s.scale.load()));
    glGenTextures(1, &s.out_texture);
    glBindTexture(GL_TEXTURE_2D, s.out_texture);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, out_width(), out_height(), 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
    glGenFramebuffers(1, &s.out_fbo);
    glBindFramebuffer(GL_FRAMEBUFFER, s.out_fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, s.out_texture, 0);
}
} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <module.prx|EBOOT.ELF> [--disc dir] [--ms dir] [--frames n]"
                  << " [--dump out.ppm]\n";
        return 2;
    }
    std::string disc = ".", memstick = ".", dump = "frame.ppm", wav;
    int frames = 600, dump_every = 0;
    std::string manifest;
    std::string cheat_file;   // --cheat: load a cheat file before running
    std::vector<std::string> cheat_enable;  // --cheat-enable ID (repeatable)
    std::vector<std::uint32_t> cheat_probes;  // --cheat-probe ADDR (repeatable)
    // --scan WIDTH:VALUE  first scan for a value (VALUE="?" scans every address);
    // --scan-filter SPEC[:VALUE]  a filter applied at --scan-at (default 60).
    std::string scan_spec, scan_filter;
    int scan_at = 60;
    bool use_gl = false, threads = true;
    struct Press { int frame, length; std::uint32_t buttons; };
    std::vector<Press> presses; // --press frame:buttons_hex:length
    struct Stick { int frame, length, x, y; };
    std::vector<Stick> sticks;  // --stick frame:x,y:length (0..255, 128 = centre)
    for (int i = 2; i + 1 < argc; i += 2) {
        const std::string flag = argv[i];
        if (flag == "--disc") disc = argv[i + 1];
        else if (flag == "--ms") memstick = argv[i + 1];
        else if (flag == "--frames") frames = std::stoi(argv[i + 1]);
        else if (flag == "--dump") dump = argv[i + 1];
        else if (flag == "--dump-every") dump_every = std::stoi(argv[i + 1]);
        else if (flag == "--webfs") manifest = argv[i + 1];
        else if (flag == "--cheat") cheat_file = argv[i + 1];
        else if (flag == "--cheat-enable") cheat_enable.push_back(argv[i + 1]);
        else if (flag == "--cheat-probe") cheat_probes.push_back(static_cast<std::uint32_t>(std::stoul(argv[i + 1], nullptr, 0)));
        else if (flag == "--scan") scan_spec = argv[i + 1];
        else if (flag == "--scan-filter") scan_filter = argv[i + 1];
        else if (flag == "--scan-at") scan_at = std::stoi(argv[i + 1]);
        else if (flag == "--gl") use_gl = std::string(argv[i + 1]) != "0";
        else if (flag == "--scale") g_session.scale.store(std::stoi(argv[i + 1]));
        else if (flag == "--threads") threads = std::string(argv[i + 1]) != "0";
        else if (flag == "--wav") wav = argv[i + 1];
        else if (flag == "--press") {
            const std::string spec = argv[i + 1];
            const auto a = spec.find(':'), b = spec.rfind(':');
            presses.push_back({std::stoi(spec.substr(0, a)), std::stoi(spec.substr(b + 1u)),
                               static_cast<std::uint32_t>(std::stoul(spec.substr(a + 1u, b - a - 1u), nullptr, 16))});
        } else if (flag == "--stick") {
            const std::string spec = argv[i + 1];
            const auto a = spec.find(':'), comma = spec.find(','), b = spec.rfind(':');
            sticks.push_back({std::stoi(spec.substr(0, a)), std::stoi(spec.substr(b + 1u)),
                              std::stoi(spec.substr(a + 1u, comma - a - 1u)), std::stoi(spec.substr(comma + 1u, b - comma - 1u))});
        }
    }
    try {
        if (!start_session(argv[1], disc, memstick, PSPWEB_GUEST_PATH, manifest, disc)) return 1;
        if (!cheat_file.empty()) {
            std::ifstream in(cheat_file, std::ios::binary);
            if (!in) {
                std::cerr << "[cheat] cannot open " << cheat_file << "\n";
            } else {
                const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
                const auto result = g_session.kernel->load_cheats(text);
                std::cout << "[cheat] loaded " << result.cheats.size() << " cheats from " << cheat_file << "\n";
                for (const auto &error : result.errors) std::cerr << "[cheat] " << error << "\n";
                // Enable the requested ids (or all of them when none were named).
                if (cheat_enable.empty()) {
                    g_session.kernel->cheats().set_all_enabled(true);
                } else {
                    for (const auto &id : cheat_enable) {
                        if (!g_session.kernel->cheats().set_enabled(id, true))
                            std::cerr << "[cheat] no cheat with id " << id << "\n";
                    }
                }
                for (const auto &cheat : g_session.kernel->cheats().cheats())
                    std::cout << "[cheat] " << (cheat.enabled ? "ON  " : "off ") << cheat.id << " \"" << cheat.name << "\"\n";
            }
        }
        if (!wav.empty()) g_session.kernel->set_audio_sink(&wav_sink);
        if (use_gl) {
            g_session.use_gl = true;
            // The GE (and its GL context) gets a thread of its own unless --threads 0.
            if (threads) g_session.kernel->ge_worker().start(&init_native_gl);
            else init_native_gl();
            std::cout << "[pspweb] GE " << (g_session.kernel->ge_worker().threaded() ? "on its own thread" : "on the main thread") << "\n";
        }
        // Watchdog: reports where the guest spins when no frame completes for 5 s.
        static std::atomic<int> progress{0};
        std::thread([] {
            int last = -1;
            for (;;) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                const int now = progress.load();
                if (now == last) {
                    const auto &c = g_session.runtime->cpu();
                    std::cerr << "[watchdog] no frame for 5 s: dispatch=0x" << std::hex << psprecomp::runtime_dispatch_pc()
                              << " thread=" << std::dec << psprecomp::runtime_thread_name() << std::hex
                              << " ra=0x" << c.gpr[31] << " sp=0x" << c.gpr[29] << " v0=0x" << c.gpr[2]
                              << " a0=0x" << c.gpr[4] << " a1=0x" << c.gpr[5] << " s0=0x" << c.gpr[16]
                              << " s1=0x" << c.gpr[17] << std::dec << std::endl;
                }
                last = now;
            }
        }).detach();
        int frame = 0;
        auto window_start = std::chrono::steady_clock::now();
        std::uint64_t last_flips = 0;
        while (frame < frames) {
            std::uint32_t buttons = 0u;
            for (const auto &p : presses)
                if (frame >= p.frame && frame < p.frame + p.length) buttons |= p.buttons;
            int lx = 128, ly = 128;
            for (const auto &s : sticks)
                if (frame >= s.frame && frame < s.frame + s.length) lx = s.x, ly = s.y;
            g_session.kernel->set_pad(buttons, static_cast<std::uint8_t>(lx), static_cast<std::uint8_t>(ly));
            if (!step(50.0)) break;
            ++frame;
            progress.store(frame);
            // --scan / --scan-filter: exercise the cheat finder natively, so its
            // logic is testable without a browser.  The scan runs once the guest
            // has settled (frame == scan_at); a filter runs a few frames later.
            if (!scan_spec.empty() && frame == scan_at) {
                const auto colon = scan_spec.find(':');
                const int width = std::stoi(scan_spec.substr(0, colon));
                const std::string value_text = colon == std::string::npos ? "" : scan_spec.substr(colon + 1u);
                const bool unknown = value_text == "?" || value_text.empty();
                const std::uint32_t value = unknown ? 0u : static_cast<std::uint32_t>(std::stoul(value_text, nullptr, 0));
                const pspweb::ScanWidth w = width == 1 ? pspweb::ScanWidth::B8 : width == 2 ? pspweb::ScanWidth::B16 : pspweb::ScanWidth::B32;
                const pspweb::ScanResult r = g_session.kernel->scanner().first_scan(pspweb::ScanRegion::UserRam, w, value, unknown);
                std::cout << "[scan] " << r.note << "\n";
                for (std::size_t i = 0; i < std::min<std::size_t>(r.hits.size(), 8u); ++i)
                    std::cout << "[scan]   0x" << std::hex << std::uppercase << r.hits[i].address
                              << " = 0x" << std::setw(8) << std::setfill('0') << r.hits[i].value << std::dec << "\n";
            }
            if (!scan_filter.empty() && frame == scan_at + scan_at) {
                const auto colon = scan_filter.find(':');
                const std::string key = scan_filter.substr(0, colon);
                const std::uint32_t value = colon == std::string::npos ? 0u
                    : static_cast<std::uint32_t>(std::stoul(scan_filter.substr(colon + 1u), nullptr, 0));
                const pspweb::ScanFilter f = key == "equal" ? pspweb::ScanFilter::Equal
                                   : key == "not-equal" ? pspweb::ScanFilter::NotEqual
                                   : key == "unchanged" ? pspweb::ScanFilter::Unchanged
                                   : key == "increased" ? pspweb::ScanFilter::Increased
                                   : key == "decreased" ? pspweb::ScanFilter::Decreased
                                                         : pspweb::ScanFilter::Changed;
                const pspweb::ScanResult r = g_session.kernel->scanner().filter(f, value);
                std::cout << "[scan] filter " << key << ": " << r.note << "\n";
                for (std::size_t i = 0; i < std::min<std::size_t>(r.hits.size(), 8u); ++i)
                    std::cout << "[scan]   0x" << std::hex << std::uppercase << r.hits[i].address
                              << " = 0x" << std::setw(8) << std::setfill('0') << r.hits[i].value << std::dec << "\n";
            }
            // --cheat-probe: report each watched word once per frame so a cheat's
            // effect (or its absence) is visible without a debugger.
            if (!cheat_probes.empty()) {
                std::cout << "[cheat-probe frame " << frame << "]";
                for (std::uint32_t addr : cheat_probes)
                    std::cout << " 0x" << std::hex << std::uppercase << addr << "=0x"
                              << std::setw(8) << std::setfill('0')
                              << g_session.runtime->memory().load32(addr) << std::dec;
                std::cout << "\n";
            }
            const auto &ge = g_session.kernel->ge().stats();
            if (frame % 60 == 0) {
                std::cout << "[frame " << frame << "] fb=0x" << std::hex << g_session.kernel->display().framebuffer
                          << std::dec << " ge lists=" << ge.lists << " prims=" << ge.prims << " tris=" << ge.triangles
                          << " culled=" << ge.culled
                          << " sprites=" << ge.sprites << " pixels=" << ge.pixels << " transfers=" << ge.transfers
                          << " flips=" << g_session.kernel->display().flips - last_flips
                          << " ge_ms/frame=" << ge.nanoseconds / 60000000.0
                          << " frame_ms=" << std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - window_start).count() / 60.0 << "\n";
                window_start = std::chrono::steady_clock::now();
                last_flips = g_session.kernel->display().flips;
                g_session.kernel->ge().reset_stats();
                if (g_session.gl) {
                    std::cout << "[frame " << frame << "] gl draw calls/frame=" << g_session.gl->draw_calls() / 60.0
                              << " downloads/frame=" << g_session.gl->downloads() / 60.0
                              << " uploads/frame=" << g_session.gl->uploads() / 60.0
                              << " upload_kpx/frame=" << g_session.gl->upload_pixels() / 60.0 / 1000.0 << "\n";
                    const auto &p = g_session.gl->passes();
                    std::cout << "[frame " << frame << "] gl passes/frame: alpha=" << p.alpha_resolves / 60.0
                              << " stencil=" << p.stencil_resolves / 60.0 << " reinterpret=" << p.reinterprets / 60.0
                              << " feedback=" << p.feedback_copies / 60.0 << " blits=" << p.blits / 60.0
                              << " extra_mpx=" << p.pixels / 60.0 / 1e6 << "\n";
                    g_session.gl->reset_passes();
                    if (frame >= 900 && std::getenv("PSPWEB_GE_PROFILE") != nullptr) g_session.gl->report_targets();
                    g_session.gl->reset_counters();
                }
                if (frame >= 900) pspweb::Ge::report_targets();
            }
            if (dump_every > 0 && frame % dump_every == 0) {
                capture_gl();
                write_ppm(dump + "." + std::to_string(frame) + ".ppm", g_session.rgba, capture_width(), capture_height());
            }
        }
        std::cout << "[pspweb] ran " << frame << " frames, vcount=" << g_session.kernel->display().vcount
                  << ", framebuffer=0x" << std::hex << g_session.kernel->display().framebuffer << std::dec << "\n";
        capture_gl();
        write_ppm(dump, g_session.rgba, capture_width(), capture_height());
        std::cout << "[pspweb] wrote " << dump << "\n";
        if (!wav.empty()) {
            write_wav(wav);
            std::cout << "[pspweb] wrote " << wav << " (" << g_wav.size() / 2u / 44100.0 << " s)\n";
        }
        g_session.kernel->dump_threads();
    } catch (const std::exception &e) {
        std::cerr << "[pspweb] fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

#endif
