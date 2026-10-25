#pragma once

// The cheat finder: a memory scanner that makes it possible to discover the
// address of a value (health, ammo, a timer) while the game runs, without a
// debugger.  It is the authoring half of the cheat feature: the engine in
// cheats.hpp *applies* addresses, this class *finds* them.
//
// The workflow is the one every emulator cheat search uses:
//
//   1. First scan:  "the value I want is N" (or "unknown" to start from every
//      address), which records a candidate set and a snapshot of memory.
//   2. Play a little (take damage, spend a bullet).
//   3. Filter:  "the value changed / decreased / increased / is still N",
//      which compares fresh memory against the snapshot and keeps the addresses
//      that still match.  Repeat until a handful of candidates remain.
//   4. Turn a candidate into a `cheat` block (format_cheats) and test it.
//
// Snapshots live in host buffers here, not in JavaScript: a full scan of the
// user partition is 32 MB, and filtering is then a cheap walk over two buffers
// that never has to be marshalled across the wasm/JS boundary.
//
// See docs/cheats.md ("Finding a cheat in the browser").

#include <cstdint>
#include <string>
#include <vector>

namespace psprecomp {
class GuestMemory;
}

namespace pspweb {

// How wide a value is compared.  Mirrors CheatWidth's memory cases but is kept
// separate so the scanner does not depend on the cheat parser.
enum class ScanWidth : std::uint8_t { B8, B16, B32 };

// A region the scanner can walk.  Only main RAM for now; VRAM is drawn by the
// GE thread and would need its reads queued through GeWorker, so it is left out
// of the first version.
enum class ScanRegion : std::uint8_t { UserRam, Vram };

// What a filter compares, run against the previous snapshot.
enum class ScanFilter : std::uint8_t {
    Equal,      // value == the value given this call
    NotEqual,   // value != the value given this call
    Changed,    // value != value in the previous snapshot
    Unchanged,  // value == value in the previous snapshot
    Increased,  // value >  value in the previous snapshot
    Decreased,  // value <  value in the previous snapshot
};

// One surviving address and the value seen there on the last scan.
struct ScanHit {
    std::uint32_t address = 0u;
    std::uint32_t value = 0u;
};

struct ScanResult {
    std::vector<ScanHit> hits;   // capped at kMaxResults, nearest-first
    std::size_t total = 0u;      // total matches, before the cap
    std::string note;            // human-readable summary/error
    bool ok = true;              // false: the call was rejected (see `note`)
};

class MemoryScanner {
public:
    // Results handed to the UI are capped, because a first "unknown" scan can
    // match 8 million addresses and no panel wants to render that.
    static constexpr std::size_t kMaxResults = 4096u;

    void set_memory(psprecomp::GuestMemory *memory) noexcept { memory_ = memory; }

    // First scan: replaces the candidate set with every address in `region`
    // that holds `value` (or every address when `unknown` is true).  Records a
    // snapshot of the region so the next call can be a filter.
    ScanResult first_scan(ScanRegion region, ScanWidth width, std::uint32_t value, bool unknown);

    // Filter: keeps only the candidates whose current value satisfies `filter`
    // (`value` is used by Equal / NotEqual) and re-snapshots memory.
    ScanResult filter(ScanFilter filter, std::uint32_t value);

    // Re-reads the current value at every candidate without narrowing the set,
    // so the panel can show live values while the game runs.
    ScanResult refresh();

    // Current candidates and their live values.  Empty before a first scan.
    [[nodiscard]] ScanResult current() const;
    [[nodiscard]] bool active() const noexcept { return active_; }
    void clear();

private:
    // Reads `width` bytes at `address`, little-endian, or returns `fallback` if
    // the read is not wholly inside memory.
    [[nodiscard]] std::uint32_t read_value(std::uint32_t address, ScanWidth width,
                                           std::uint32_t fallback) const;

    // Reads the snapshot's value at `offset` bytes into the region.
    [[nodiscard]] std::uint32_t snapshot_value(std::uint32_t offset, ScanWidth width) const;

    psprecomp::GuestMemory *memory_ = nullptr;
    bool active_ = false;
    ScanRegion region_ = ScanRegion::UserRam;
    ScanWidth width_ = ScanWidth::B32;
    // Candidate addresses only, one entry each; their values live in snapshot_
    // (indexed by address - region_base_), so a first "unknown" scan of 6 million
    // addresses costs 24 MB, not 48, and the live value is always read fresh.
    std::vector<std::uint32_t> candidates_;
    std::vector<std::uint8_t> snapshot_;   // one snapshot of the whole region
    std::uint32_t region_base_ = 0u;
    std::uint32_t region_size_ = 0u;
};

} // namespace pspweb
