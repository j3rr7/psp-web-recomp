#pragma once

// The cheat engine: a small, self-contained subsystem that lets a user load a
// CWCheat-flavoured text file and have it applied to the guest each frame.
//
// See docs/cheats.md for the file format and the list of host actions.

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace psprecomp {
class GuestMemory;
}

namespace pspweb {

// Width of a single memory poke.
enum class CheatWidth : std::uint8_t { B8, B16, B32, Block };

// When an entry is applied.
enum class CheatMode : std::uint8_t {
    Once,        // written on the frame the cheat is enabled, then forgotten
    EveryFrame,  // re-written every frame while the cheat is enabled
    Conditional, // written every frame, but only while the joker compare holds
};

// How a Conditional entrys is satisfied.
enum class CheatTest : std::uint8_t {
    Equal,     // apply while memory[cond_address] == cond_value
    NotEqual,  // apply while memory[cond_address] != cond_value
    LessThan,  // apply while memory[cond_address] <  cond_value
    GreaterThan,
};

struct CheatEntry {
    CheatMode mode = CheatMode::EveryFrame;
    // Memory poke.
    std::uint32_t address = 0u;
    std::uint32_t value = 0u;
    CheatWidth width = CheatWidth::B32;
    std::vector<std::uint8_t> block;      // width == Block
    // Joker (mode == Conditional).  A cond_width of B8/B16/B32 picks the read size.
    std::uint32_t cond_address = 0u;
    std::uint32_t cond_value = 0u;
    CheatWidth cond_width = CheatWidth::B32;
    CheatTest test = CheatTest::Equal;
    // Host action ("" = a pure memory poke).  `args` are action-specific.
    std::string action;
    std::vector<std::uint32_t> args;
    // Runtime bookkeeping: set once a Once entry has fired.
    bool applied_once = false;
};

struct Cheat {
    std::string id;    // stable identifier, e.g. "INF_HEALTH"
    std::string name;  // label shown in the UI
    bool enabled = false;
    std::vector<CheatEntry> entries;
};

// Result of loading a file: the cheats that parsed, plus any diagnostics.
struct CheatLoadResult {
    std::vector<Cheat> cheats;
    std::vector<std::string> errors;  // "line 12: unknown width" etc.
    bool ok() const noexcept { return !cheats.empty(); }
};

// Parses CWCheat-flavoured text.  Never throws; malformed lines are collected
// in `errors` with their line numbers and skipped, so one bad line does not
// discard an otherwise usable file.
CheatLoadResult parse_cheats(const std::string &text);

// Serialises a set of cheats back to the same text format.
std::string format_cheats(const std::vector<Cheat> &cheats);

// ---------------------------------------------------------------------------
// The engine.  It owns the loaded cheats, applies them once per frame, and
// resolves host actions against a registry the Kernel fills in.

class CheatEngine {
public:
    using Action = std::function<void(const CheatEntry &)>;

    // Registers a host action by name.  Called from Kernel::install().
    void register_action(std::string name, Action action);
    [[nodiscard]] bool has_action(const std::string &name) const;

    // Replaces the loaded set.  Enabling state is preserved for cheats whose id
    // is already present, so toggling a cheat is not lost when the file reloads.
    void set_cheats(CheatLoadResult loaded);
    [[nodiscard]] const std::vector<Cheat> &cheats() const noexcept { return cheats_; }
    [[nodiscard]] const std::vector<std::string> &errors() const noexcept { return errors_; }

    // Enables or disables one cheat by id.  Returns false if no such id.
    bool set_enabled(const std::string &id, bool enabled);
    // Enables or disables every loaded cheat.
    void set_all_enabled(bool enabled);
    [[nodiscard]] bool any_enabled() const noexcept;

    // Applies every enabled cheat for one frame.  `memory` is the guest memory;
    // a null-safe helper that canonicalises and bounds-checks.  Called from
    // Kernel::frame() at the top of the frame, before guest code runs.
    void apply_frame();

    // Clears the "already fired" flag on Once entries (for a fresh session).
    void reset_once_flags();

    void set_memory(psprecomp::GuestMemory *memory) noexcept { memory_ = memory; }

private:
    void apply_entry(CheatEntry &entry);

    std::vector<Cheat> cheats_;
    std::vector<std::string> errors_;
    std::map<std::string, Action, std::less<>> actions_;
    psprecomp::GuestMemory *memory_ = nullptr;
};

} // namespace pspweb
