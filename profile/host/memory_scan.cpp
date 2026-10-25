#include "memory_scan.hpp"

#include "kernel.hpp"

#include "psprecomp/guest_memory.hpp"

#include <algorithm>
#include <cstdio>

namespace pspweb {
namespace {

// step between candidate addresses for a given width; a scan of b16 does not
// have to test odd addresses that a halfword load would straddle.
std::uint32_t scan_step(ScanWidth width) {
    switch (width) {
    case ScanWidth::B8: return 1u;
    case ScanWidth::B16: return 2u;
    case ScanWidth::B32: return 4u;
    }
    return 4u;
}

std::uint32_t width_mask(ScanWidth width) {
    switch (width) {
    case ScanWidth::B8: return 0xFFu;
    case ScanWidth::B16: return 0xFFFFu;
    case ScanWidth::B32: return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu;
}

const char *width_name(ScanWidth width) {
    switch (width) {
    case ScanWidth::B8: return "b8";
    case ScanWidth::B16: return "b16";
    case ScanWidth::B32: return "b32";
    }
    return "b32";
}

std::string hex32(std::uint32_t value) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08X", value);
    return buf;
}

} // namespace

void MemoryScanner::clear() {
    active_ = false;
    candidates_.clear();
    snapshot_.clear();
    region_base_ = region_size_ = 0u;
}

std::uint32_t MemoryScanner::read_value(std::uint32_t address, ScanWidth width,
                                        std::uint32_t fallback) const {
    if (memory_ == nullptr) return fallback;
    switch (width) {
    case ScanWidth::B8:
        return memory_->contains(address, 1u) ? memory_->load8(address) : fallback;
    case ScanWidth::B16:
        return memory_->contains(address, 2u) ? memory_->load16(address) : fallback;
    case ScanWidth::B32:
        return memory_->contains(address, 4u) ? memory_->load32(address) : fallback;
    }
    return fallback;
}

std::uint32_t MemoryScanner::snapshot_value(std::uint32_t offset, ScanWidth width) const {
    const std::uint8_t *base = snapshot_.data() + offset;
    switch (width) {
    case ScanWidth::B8: return base[0];
    case ScanWidth::B16: return static_cast<std::uint32_t>(base[0]) | (static_cast<std::uint32_t>(base[1]) << 8u);
    case ScanWidth::B32:
        return static_cast<std::uint32_t>(base[0]) | (static_cast<std::uint32_t>(base[1]) << 8u) |
               (static_cast<std::uint32_t>(base[2]) << 16u) | (static_cast<std::uint32_t>(base[3]) << 24u);
    }
    return 0u;
}

ScanResult MemoryScanner::first_scan(ScanRegion region, ScanWidth width, std::uint32_t value, bool unknown) {
    ScanResult result;
    if (memory_ == nullptr) {
        result.ok = false;
        result.note = "no guest memory";
        return result;
    }
    if (region == ScanRegion::Vram) {
        // VRAM is written by the GE thread; a raw read here would race it.  Kept
        // out of the first version on purpose (see memory_scan.hpp).
        result.ok = false;
        result.note = "VRAM scanning is not supported yet; scan RAM instead";
        return result;
    }

    region_ = region;
    width_ = width;
    region_base_ = kUserPartitionStart;
    region_size_ = kUserPartitionEnd - kUserPartitionStart;
    // A snapshot of the whole region, so filters can compare any candidate
    // address without re-reading (and without the value drifting mid-scan).
    snapshot_.assign(region_size_, 0u);
    memory_->copy_out(region_base_, std::span<std::uint8_t>(snapshot_.data(), snapshot_.size()));

    const std::uint32_t mask = width_mask(width);
    const std::uint32_t wanted = value & mask;
    const std::uint32_t step = scan_step(width);
    candidates_.clear();
    for (std::uint32_t offset = 0u; offset + step <= region_size_; offset += step) {
        const std::uint32_t at = region_base_ + offset;
        if (!memory_->contains(at, step)) continue;
        const std::uint32_t current = snapshot_value(offset, width);
        if (unknown || current == wanted) candidates_.push_back(at);
    }

    active_ = true;
    result.total = candidates_.size();
    // The full candidate set is kept; only what is *reported* is capped.  A
    // finder that dropped candidates to fit the UI would silently lose the
    // address the user is looking for.
    const std::size_t shown = std::min(candidates_.size(), kMaxResults);
    result.hits.reserve(shown);
    for (std::size_t i = 0; i < shown; ++i) {
        ScanHit hit;
        hit.address = candidates_[i];
        hit.value = snapshot_value(candidates_[i] - region_base_, width);
        result.hits.push_back(hit);
    }
    result.note = std::string(unknown ? "unknown-value" : "value " + hex32(wanted)) + " " +
                  width_name(width) + ": " + std::to_string(result.total) + " candidate(s)";
    return result;
}

ScanResult MemoryScanner::filter(ScanFilter filter, std::uint32_t value) {
    ScanResult result;
    if (!active_ || memory_ == nullptr) {
        result.ok = false;
        result.note = "no previous scan; run a first scan";
        return result;
    }

    const std::uint32_t mask = width_mask(width_);
    const std::uint32_t wanted = value & mask;
    const std::uint32_t step = scan_step(width_);

    std::vector<std::uint32_t> kept;
    kept.reserve(candidates_.size());
    for (std::uint32_t address : candidates_) {
        // `address` was validated in the previous scan, and the region and width
        // are unchanged, so it is still in range.
        const std::uint32_t offset = address - region_base_;
        if (offset + step > region_size_) continue;
        const std::uint32_t now = read_value(address, width_, 0u);
        const std::uint32_t before = snapshot_value(offset, width_);
        bool keep = false;
        switch (filter) {
        case ScanFilter::Equal: keep = now == wanted; break;
        case ScanFilter::NotEqual: keep = now != wanted; break;
        case ScanFilter::Changed: keep = now != before; break;
        case ScanFilter::Unchanged: keep = now == before; break;
        case ScanFilter::Increased: keep = now > before; break;
        case ScanFilter::Decreased: keep = now < before; break;
        }
        if (keep) kept.push_back(address);
    }

    // Re-snapshot so the *next* filter compares against this moment, not the
    // original first scan.  This is what lets "changed / unchanged" be applied
    // repeatedly while walking through the game.
    snapshot_.assign(region_size_, 0u);
    memory_->copy_out(region_base_, std::span<std::uint8_t>(snapshot_.data(), snapshot_.size()));

    candidates_ = std::move(kept);
    result = current();
    result.note = std::to_string(result.total) + " candidate(s) remain";
    return result;
}

ScanResult MemoryScanner::refresh() {
    ScanResult result;
    if (!active_ || memory_ == nullptr) {
        result.ok = false;
        result.note = "no scan in progress";
        return result;
    }
    return current();
}

ScanResult MemoryScanner::current() const {
    ScanResult result;
    if (!active_) {
        result.ok = false;
        result.note = "no scan in progress";
        return result;
    }
    result.total = candidates_.size();
    const std::size_t shown = std::min(candidates_.size(), kMaxResults);
    result.hits.reserve(shown);
    for (std::size_t i = 0; i < shown; ++i) {
        ScanHit hit;
        hit.address = candidates_[i];
        hit.value = read_value(candidates_[i], width_, 0u);
        result.hits.push_back(hit);
    }
    result.note = std::to_string(result.total) + " candidate(s)";
    return result;
}

} // namespace pspweb
